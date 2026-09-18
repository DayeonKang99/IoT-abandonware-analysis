from typing import List, Optional, Set
import os
import xmltodict
from xml.etree.ElementTree import Element, tostring, parse
from xml.parsers.expat import ExpatError
from run.icc_connection import parse_iotscope, ValuePoint, get_value_point, create_key_map
import json
import run.icc_connection
#import importlib
#import parse_ip
#importlib.reload(parse_ip)
from parse_ip import parse_ip_or_domain, parse_all

app_num = 58669

class StatementLocation:
    def __init__(self, statement, parent_method, line_number):
        self.statement = statement
        self.parent_method = parent_method
        self.line_number = line_number
        self.value_scope_results = []

    def set_source_values(self, value_scope_results: List[ValuePoint]):
        self.value_scope_results = value_scope_results

    def __str__(self):
        return f"ICC(stmt: {self.statement}, parent_method: {self.parent_method}, line_number {self.line_number})"

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash((self.parent_method, self.line_number))

    def __eq__(self, other):
        if other is None:
            return False
        return (self.parent_method, self.line_number) == (other.parent_method, other.line_number)

    def __ne__(self, other):
        # Not strictly necessary, but to avoid having both x==y and x!=y
        # True at the same time
        return not (self == other)


class FlowDroidResult:
    def __init__(self, sink: StatementLocation, sources: List[StatementLocation]):
        self.sink = sink
        self.sources = sources

    def __hash__(self):
        return hash((self.sink, self.sources))

    def __eq__(self, other):
        if other is None:
            return False
        return (self.sink, self.sources) == (other.sink, other.sources)

    def __ne__(self, other):
        # Not strictly necessary, but to avoid having both x==y and x!=y
        # True at the same time
        return not (self == other)


class AppResult:
    def __init__(self, flows: List[FlowDroidResult], call_graph_construction_seconds, taint_propagation_seconds,
                 path_reconstruction_seconds, total_runtime, max_memory_consumption, path: Optional[str]):
        self.flows = flows
        self.call_graph_construction_seconds = call_graph_construction_seconds
        self.taint_propagation_seconds = taint_propagation_seconds
        self.path_reconstruction_seconds = path_reconstruction_seconds
        self.total_runtime = total_runtime
        self.max_memory_consumption = max_memory_consumption
        self.path = path


class FlowDroidRun:
    def __init__(self, to_icc_or_sink: AppResult, from_icc_to_sink: AppResult, app_id: str, sources: List[ValuePoint],
                 sinks: List[ValuePoint], both: Optional[List[AppResult]] = None,
                 source_connections: Optional[List[AppResult]] = None,
                 sink_connections: Optional[List[AppResult]] = None, iot_scope_results: List[ValuePoint] = None):
        self.to_icc_or_sink = to_icc_or_sink
        self.from_icc_to_sink = from_icc_to_sink
        self.sources = sources
        self.sinks = sinks
        self.app_id = app_id
        self.both = both
        self.source_connections = source_connections
        self.sink_connections = sink_connections
        self.iot_scope_results = iot_scope_results


class PotentialLeak:

    def __init__(self, sources: List[StatementLocation], icc_sink: Optional[StatementLocation],
                 icc_source: Optional[List[StatementLocation]], sink: StatementLocation):
        self.sources = sources
        self.icc_sink = icc_sink
        self.icc_source = icc_source
        self.sink = sink

    def __str__(self):
        return f"Flow(stmt: {self.sources}, parent_method: {self.icc_sink}, keys {self.icc_source}, line_number {self.sink})"

    def __repr__(self):
        return self.__str__()


class AnalyzedApp:
    def __init__(self, app_data: FlowDroidRun, potentialLeaks: List[PotentialLeak]):
        self.source_connections = {}
        self.sink_connections = {}
        self.app_data = app_data
        self.potentialLeaks = potentialLeaks

    def get_values(self, stmt: StatementLocation):
        keys: Set = set()
        for vp in self.app_data.iot_scope_results:
            if (vp.parent_method == stmt.parent_method) and (int(vp.line_number) == int(stmt.line_number)):
                keys.update(vp.keys)

        return keys

    def add_source_values(self, sources: List[StatementLocation]) -> List[StatementLocation]:
        result = []
        for source in sources:
            keys = self.get_values(source)
            source.set_source_values(keys)
            result.append(source)

        return result

    def set_sink_connection(self, leak: PotentialLeak, sources: List[StatementLocation]):
        tmp = self.sink_connections.get(leak, [])
        tmp.extend(self.add_source_values(sources))
        self.sink_connections[leak] = tmp

    def set_source_connection(self, leak: PotentialLeak, sources: List[StatementLocation]):
        tmp = self.source_connections.get(leak, [])
        tmp.extend(self.add_source_values(sources))
        self.source_connections[leak] = tmp


def get_statement_location(flowdroid_statement):
    statement = flowdroid_statement.get("@Statement", "<>")
    statement = statement[statement.index("<"): statement.index(">") + 1]
    parent_method = flowdroid_statement.get("@Method", "")
    line_number = flowdroid_statement.get("@LineNumber", -1)
    return StatementLocation(statement, parent_method, line_number)

def parse_flowdroid(path) -> AppResult:
    flows = []
    iotflow_result = None
    # load stmt if key is not available look at the icc
    try:
        with open(path, "r") as xml_obj:
            # coverting the xml data to Python dictionary
            iotflow_result = xmltodict.parse(xml_obj.read())
            # closing the file
            xml_obj.close()
        if iotflow_result is not None:
            # print(json.dumps(iotflow_result))
            flow_result = iotflow_result.get("DataFlowResults", {})
            results = flow_result.get("Results", {})
            all_results = results.get("Result", [])
            if type(all_results) is not type([]):
                all_results = [all_results]
            for result in all_results:
                sink = result.get("Sink", {})
                sources = result.get("Sources", {})
                current_sink = get_value_point(sink)
                all_sources = sources.get("Source", [])
                current_sources = []

                if type(all_sources) is not type([]):
                    all_sources = [all_sources]
                for source in all_sources:
                    current_source = get_value_point(source)
                    current_sources.append(current_source)

                flows.append(FlowDroidResult(current_sink, current_sources))

        cgc = None
        tp = None
        pr = None
        tr = None
        mm = None
        # data_flow_result = xml_data.find("DataFlowResults")
        xml_data: Element = parse(path).getroot()

        performance_data = xml_data.find("PerformanceData")
        if performance_data is not None:
            for performance_entry in performance_data.findall("PerformanceEntry"):
                if performance_entry.get("Name") == "CallgraphConstructionSeconds":
                    cgc = (int(performance_entry.get("Value")))
                elif performance_entry.get("Name") == "TaintPropagationSeconds":
                    tp = (int(performance_entry.get("Value")))
                elif performance_entry.get("Name") == "PathReconstructionSeconds":
                    pr = (int(performance_entry.get("Value")))
                elif performance_entry.get("Name") == "TotalRuntimeSeconds":
                    tr = (int(performance_entry.get("Value")))
                elif performance_entry.get("Name") == "MaxMemoryConsumption":
                    mm = (int(performance_entry.get("Value")))

        return AppResult(flows, cgc, tp, pr, tr, mm, path)

    except ExpatError as e:
        print(path)
        print(e)
        pass

    return None

def get_all_from_folder(path, extension, filename):
    result = []
    folder_name = os.path.join(path, extension)
    for folder in os.listdir(folder_name):
        try:
            result.append(parse_flowdroid(os.path.join(os.path.join(folder_name, folder), filename)))
        except FileNotFoundError as e:
            print(e)

    return result


def parse_all_IoT_scope_results(path: str, json_file_name: str):
    result: List[ValuePoint] = []
    try:
        tmp = parse_iotscope(os.path.join(os.path.join(path, "amqp"), json_file_name))
        result.extend(tmp)
    except FileNotFoundError as e:
        #print(e)
        pass

    try:
        tmp = parse_iotscope(os.path.join(os.path.join(path, "coap"), json_file_name))
        result.extend(tmp)
    except FileNotFoundError as e:
        #print(e)
        pass

    try:
        tmp = parse_iotscope(os.path.join(os.path.join(path, "endpoints"), json_file_name))
        result.extend(tmp)
    except FileNotFoundError as e:
        #print(e)
        pass

    try:
        tmp = parse_iotscope(os.path.join(os.path.join(path, "mqtt"), json_file_name))
        result.extend(tmp)
    except FileNotFoundError as e:
        #print(e)
        pass

    try:
        tmp = parse_iotscope(os.path.join(os.path.join(path, "udp"), json_file_name))
        result.extend(tmp)
    except FileNotFoundError as e:
        #print(e)
        pass
    try:
        tmp = parse_iotscope(os.path.join(os.path.join(path, "webview"), json_file_name))
        result.extend(tmp)
    except FileNotFoundError as e:
        #print(e)
        pass

    try:
        tmp = parse_iotscope(os.path.join(os.path.join(path, "xmpp"), json_file_name))
        result.extend(tmp)
    except FileNotFoundError as e:
        #print(e)
        pass
    return result


def parse_dataset(path: str, prefix) -> List[FlowDroidRun]:
    #both
    #sink_connection
    #source_connection
    result = []
    for f in os.listdir(os.path.join(path, f"{prefix}_to_icc_or_sink")):
        try:
            to_icc = parse_flowdroid(os.path.join(os.path.join(path, f"{prefix}_to_icc_or_sink"), f))
        except FileNotFoundError as e:
            #print(e)
            to_icc = None

        try:
            from_icc = parse_flowdroid(os.path.join(os.path.join(path, f"{prefix}_from_icc_to_sink"), f))
        except FileNotFoundError as e:
            #print(e)
            from_icc = None

        try:
            sources = parse_iotscope(os.path.join(os.path.join(path, "sources"), f.replace(".xml", ".json")))
        except FileNotFoundError as e:
            #print(e)
            sources = None

        try:
            sinks = parse_iotscope(os.path.join(os.path.join(path, "sinks"), f.replace(".xml", ".json")))
        except FileNotFoundError as e:
            #print(e)
            sinks = None

        both = get_all_from_folder(path, "both", f)
        source_connections = get_all_from_folder(path, "source_connection", f)
        sink_connections = get_all_from_folder(path, "sink_connection", f)

        app_name = f[0:len(f) - len(".xml")]
        result.append(
            FlowDroidRun(to_icc, from_icc, app_name, sources, sinks, both, source_connections, sink_connections,
                         parse_all_IoT_scope_results(path, f.replace(".xml", ".json"))))

    return result


def parse_local_dataset(path: str) -> List[FlowDroidRun]:
    return parse_dataset(path, "local")


def parse_bl_dataset(path: str) -> List[FlowDroidRun]:
    return parse_dataset(path, "bl")


def parse_general_dataset(path: str) -> List[FlowDroidRun]:
    return parse_dataset(path, "general")

def get_icc_sinks(path_bl_run_config):
    sinks = set()
    xml_template: Element = parse(path_bl_run_config).getroot()
    category = xml_template.findall("category")
    for category in category:
        for method in category.findall("method"):
            method_signature = method.get("signature")
            params = method.findall("param") + method.findall("base") + method.findall("return")
            #print(len(params))
            for param in params:
                access_path = param.find("accessPath")

                if access_path.get("isSink") == "true":
                    if method_signature.startswith("android.content.Intent:") or method_signature.startswith(
                            "android.content.SharedPreferences$Editor:") or method_signature.startswith(
                        "android.os.Bundle:"):
                        sinks.add(method_signature)

    return sinks
def filter_apps(dataset: List[FlowDroidRun], name, mapping) -> List[FlowDroidRun]:
    result = []
    for app in dataset:
        app_name = app.app_id
        if app_name in mapping:
            if mapping[app_name] == name:
                result.append(app)
        else:
            result.append(app)
    return result


def parse_verified_dataset(base_path, mapping_file, prefix):
    mapping_json = {}
    with open(mapping_file, "r") as f:
        mapping_json = json.load(f)

    neupane = parse_dataset(os.path.join(base_path, "neupane"), prefix)
    neupane = filter_apps(neupane, "neupane", mapping_json, )

    iotspotter = parse_dataset(os.path.join(base_path, "iotspotter"), prefix)
    iotspotter = filter_apps(iotspotter, "iotspotter", mapping_json)

    iotprofiler = parse_dataset(os.path.join(base_path, "iotprofiler"), prefix)
    iotprofiler = filter_apps(iotprofiler, "iotprofiler", mapping_json)

    return neupane + iotprofiler + iotspotter


def parse_verified_dataset_local(path: str, mapping_file) -> List[FlowDroidRun]:
    return parse_verified_dataset(path, mapping_file, "local")


def parse_verified_dataset_bl(path: str, mapping_file) -> List[FlowDroidRun]:
    return parse_verified_dataset(path, mapping_file, "bl")


def parse_verified_dataset_general(path: str, mapping_file) -> List[FlowDroidRun]:
    return parse_verified_dataset(path, mapping_file, "general")


def get_method(signature: str):
    signature = signature.strip()
    signature_splitted = signature.split(" ")
    if len(signature_splitted) >= 2:
        result = signature_splitted[2]
        if result.endswith(">"):
            result = result[0: len(result) - 1]
        return result

    return signature


def get_only_method_list(signature_list: List[str]):
    result = []
    for signature in signature_list:
        result.append(get_method(signature))

    return result

def get_sink_keys(sinks: List[ValuePoint], stmt: StatementLocation):
    result = []
    if sinks is not None and stmt is not None:
        for sink in sinks:
            if sink.parent_method == stmt.parent_method and int(sink.line_number) == int(stmt.line_number):
                return sink.keys
    #print(result)
    return result

def does_already_contain_flow(result: List[FlowDroidResult], flow: FlowDroidResult):
    if flow in result:
        #print("old flow")
        return True

    #print("new flow")
    return False


def get_matching_flows_from_icc(potential_sources: List[ValuePoint], icc_to_sink_run: AppResult):
    result = []
    if icc_to_sink_run is not None and icc_to_sink_run.flows is not None:
        for flow in icc_to_sink_run.flows:
            if flow.sources is not None:
                for source in flow.sources:
                    for ps in potential_sources:
                        if source.parent_method == ps.parent_method and int(ps.line_number) == int(source.line_number):
                            if not does_already_contain_flow(result, flow):
                                result.append(flow)

                    #print(type(potential_sources[0]))
                    #if ValuePoint(source.stmt,source.parent_method,None, source.line_number) in potential_sources:
                    #    print("match")
                    #    result.append(flow)

    return result


def get_matching_flows(app_result: FlowDroidRun, icc_sinks) -> List[PotentialLeak]:
    result_list: List[PotentialLeak] = []
    if app_result.to_icc_or_sink is None or app_result.to_icc_or_sink.flows is None:
        return result_list

    source_map = {}
    if app_result.sources is not None:
        source_map = create_key_map(app_result.sources)

    for result in app_result.to_icc_or_sink.flows:
        if get_method(result.sink.stmt) in icc_sinks:
            #print(app_result.sources)
            keys = get_sink_keys(app_result.sinks, result.sink)
            #import time
            #time.sleep(0.01)
            #print("---------")
            #print(keys)
            #print(source_map)
            #print("---------")

            # get stmt and  match connection
            for key in keys:
                #print(key)
                if key in source_map:
                    #print(key)
                    flows = get_matching_flows_from_icc(source_map[key], app_result.from_icc_to_sink)
                    for flow in flows:
                        result_list.append(PotentialLeak(result.sources, result.sink, flow.sources, flow.sink))
                        #print("match")

        else:
            result_list.append(PotentialLeak(result.sources, None, None, result.sink))
            # found a flow
    return result_list


def analyze_dataset(dataset) -> List[AnalyzedApp]:
    leaks: List[AnalyzedApp] = []
    for app in dataset:
        leaks.append(AnalyzedApp(app, get_matching_flows(app, icc_sinks_methods)))
    return leaks

def filter_java_methods(results: List[AnalyzedApp]) -> List[AnalyzedApp]:
    keywords_of_false_positives = ["ArchiveInputStream", "FileOutputStream", "Zip", "Disk", "bluetooth", "Bluetooth",
                                   "java.util.zip", "zip.DeflaterOutputStream", "java.io.FileWriter", "writeToFile",
                                   "saveTxtFile", "writetoSDCard"]
    filtered_results: List[AnalyzedApp] = []
    for app in results:
        current_result: List[PotentialLeak] = []
        for app_result in app.potentialLeaks:
            contains_keyword = False
            if not app_result.sink.stmt.replace("<", "").startswith("java.io"):
                current_result.append(app_result)
                continue
            for keyword in keywords_of_false_positives:
                #print(type(app_result.sink))
                if keyword in app_result.sink.parent_method or keyword in app_result.sink.stmt:
                    contains_keyword = True

            if not contains_keyword:
                current_result.append(app_result)
        filtered_results.append(AnalyzedApp(app, current_result))
    return filtered_results


def get_sink_connection(analyzedApp: AnalyzedApp):
    flows = []
    if analyzedApp.app_data.both != None and analyzedApp.app_data.sink_connections:
        flows = analyzedApp.app_data.both + analyzedApp.app_data.sink_connections
    elif analyzedApp.app_data.both != None:
        flows = analyzedApp.app_data.both
    elif analyzedApp.app_data.sink_connections:
        flows = analyzedApp.app_data.sink_connections
    for run in flows:
        if run is None:
            continue
        for flow in run.flows:
            for leak in analyzedApp.potentialLeaks:
                if int(leak.sink.line_number) == int(
                        flow.sink.line_number) and leak.sink.parent_method == flow.sink.parent_method:
                    analyzedApp.set_sink_connection(leak, flow.sources)

    return analyzedApp


def get_source_connection(analyzedApp: AnalyzedApp):
    flows = []
    if analyzedApp.app_data.both != None and analyzedApp.app_data.source_connections:
        flows = analyzedApp.app_data.both + analyzedApp.app_data.source_connections
    elif analyzedApp.app_data.both != None:
        flows = analyzedApp.app_data.both
    elif analyzedApp.app_data.source_connections:
        flows = analyzedApp.app_data.source_connections

    for run in flows:
        if run is None:
            continue
        for flow in run.flows:
            for leak in analyzedApp.potentialLeaks:
                for source in leak.sources:
                    if int(source.line_number) == int(
                            flow.sink.line_number) and source.parent_method == flow.sink.parent_method:
                        analyzedApp.set_source_connection(leak, flow.sources)

    return analyzedApp


def get_all_source_sink_connection(dataset: List[AnalyzedApp]) -> List[AnalyzedApp]:
    result: List[AnalyzedApp] = []
    for app in dataset:
        current = get_sink_connection(app)
        current = get_source_connection(current)
        result.append(current)

    return result

def filter_java_sinks(dataset: List[AnalyzedApp]) -> List[AnalyzedApp]:
    result = []
    for app in dataset:
        app_leaks = []
        for leak in app.potentialLeaks:
            if leak.sink.stmt.replace("<", "").startswith("java.io"):
                if leak in app.sink_connections:
                    #print(app.sink_connections[leak])
                    app_leaks.append(leak)
            else:
                app_leaks.append(leak)

        app.potentialLeaks = app_leaks
        result.append(app)

    return result

def analyze_and_filter_datset(dataset: List[FlowDroidRun]):
    analyzed = analyze_dataset(dataset)

    analyzed = get_all_source_sink_connection(analyzed)
    return filter_java_sinks(analyzed)


import re

multicast_addresses = ['255.255.255.255', '224.0.0.', '224.0.1.', '224.0.2.', '224.1.', '224.3.', '224.4.', '225.',
                       '226.',
                       '227.', '228.', '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.', '237.',
                       '238.', '239.',
                       'ffx0:', 'ffx1:', 'ffx2:', 'ffx3:', 'ffx4:', 'ffx5:', 'ffx6:', 'ffx7:', 'ffx8:', 'ffx9:',
                       'ffxa:',
                       'ffxb:', 'ffxc:', 'ffxd:', 'ffxe:', 'ff02:', 'ff0x:']


def is_local_value(address: str) -> bool:
    local_network = re.findall(
        "(192\.168\.\d\d?\d?\.\d\d?\d?)|(10\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)|(172\.1[6-9]\.\d\d?\d?\.\d\d?\d?)|(172\.2[0-9]\.\d\d?\d?\.\d\d?\d?)|(172\.3[0-1]\.\d\d?\d?\.\d\d?\d?)|(.*[^:]fromui\.local[:\/ ])|(fd00:)|(fe80:)|(fc00:)",
        address)
    if len(local_network) > 0:
        return True

    for ma in multicast_addresses:
        if address.startswith(ma):
            return True

    return False


def has_local_value(addresses: Set[str]) -> bool:
    for address in addresses:
        if is_local_value(address):
            return True

    return False


def has_no_local_value(addresses: Set[str]) -> bool:
    for address in addresses:
        if not is_local_value(address):
            return True
    return False


def filter_local_dataset(dataset: List[AnalyzedApp], local_to_remote: bool = False):
    result: List[FlowDroidRun] = []
    for app in dataset:
        current_flows = []

        for flow in app.potentialLeaks:
            current_source_values = set()
            current_sink_values = set()

            if flow in app.source_connections:
                for sc in app.source_connections[flow]:
                    sc: StatementLocation = sc
                    current_source_values.update(sc.value_scope_results)

            if flow in app.sink_connections:
                for sc in app.sink_connections[flow]:
                    sc: StatementLocation = sc
                    current_sink_values.update(sc.value_scope_results)

            current_source_values = parse_all(current_source_values)
            current_sink_values = parse_all(current_sink_values)

            if has_local_value(current_source_values):
                if local_to_remote:
                    if has_no_local_value(current_sink_values):
                        current_flows.append(flow)
                else:
                    current_flows.append(flow)

        tmp = AnalyzedApp(app.app_data, current_flows)
        tmp.source_connections = app.source_connections
        tmp.sink_connections = app.sink_connections
        result.append(tmp)

    return result


def get_stats_general(dataset: List[AnalyzedApp]):
    count_flows = 0
    count_apps = 0
    flows_via_icc = {}
    general_count_map = {}
    general_app_map = {}

    for app in dataset:
        sources_in_app = set()
        for leak in app.potentialLeaks:
            for source in leak.sources:
                general_count_map[source.stmt] = general_count_map.get(source.stmt, 0) + 1
                sources_in_app.add(source.stmt)
                if leak.icc_sink is not None:
                    flows_via_icc[source.stmt] = flows_via_icc.get(source.stmt, 0) + 1

        for source in sources_in_app:
            general_app_map[source] = general_app_map.get(source, 0) + 1

    return general_count_map, general_app_map, flows_via_icc


def get_stats(dataset: List[AnalyzedApp]):
    count_flows = 0
    count_apps = 0
    flows_via_icc = 0
    flows_with_sink_values = 0
    apps_with_sink_values = 0

    for app in dataset:
        if len(app.potentialLeaks) > 0:
            count_flows = count_flows + len(app.potentialLeaks)
            count_apps = count_apps + 1
            has_sink_value = False
            for leak in app.potentialLeaks:
                current_sink_values = set()
                if leak.icc_source is not None and leak.icc_sink is not None:
                    flows_via_icc = flows_via_icc + 1

                if leak in app.sink_connections:
                    for sc in app.sink_connections[leak]:
                        sc: StatementLocation = sc
                        current_sink_values.update(sc.value_scope_results)

                if len(current_sink_values) > 0:
                    flows_with_sink_values = flows_with_sink_values + 1
                    has_sink_value = True

            if has_sink_value:
                apps_with_sink_values = apps_with_sink_values + 1

    return count_flows, count_apps, flows_via_icc, flows_with_sink_values, apps_with_sink_values




def get_flows_with_source_sink_connection(dataset: List[AnalyzedApp], only_if_sink_values:bool = False) -> str:
    result = ""
    for app in dataset:

        for flow in app.potentialLeaks:
            current_source_values = set()
            current_sink_values = set()

            if flow in app.source_connections:
                for sc in app.source_connections[flow]:
                    sc: StatementLocation = sc
                    current_source_values.update(sc.value_scope_results)

            if flow in app.sink_connections:
                for sc in app.sink_connections[flow]:
                    sc: StatementLocation = sc
                    current_sink_values.update(sc.value_scope_results)

            if only_if_sink_values and len(parse_all(current_sink_values)) == 0 :
                continue
            result += "--------------------------------------------------------------\n"
            if app.app_data is not None:
                result += (app.app_data.app_id + "\n")
            if len(current_source_values) > 0:
                result += f"We reconstructed for the source connection: {parse_all(current_source_values)}\n"

            result += (f"The flow was found from: {flow.sources} -------> {flow.sink}\n")
            if flow.icc_sink:
                result +=(f"Flow was found via ICC from {flow.icc_source} - {flow.icc_sink}\n")
            if len(current_sink_values) > 0:
                result +=(f"We reconstructed for the sink connection: {parse_all(current_sink_values)}\n")

            result += "--------------------------------------------------------------\n"

    return result



def print_flows_with_source_sink_connection(dataset: List[AnalyzedApp], only_if_sink_values:bool = False):
    print(get_flows_with_source_sink_connection(dataset, only_if_sink_values))

import pandas as pd


def create_row(bl, local, general):
    if bl[0] > 0:
        bl_icc = f"{bl[2]} ({bl[2]/bl[0]*100:.2f}%)"
        bl_sink = f"{bl[3]} ({bl[3]/bl[0]*100:.2f}%)"
    else:
        bl_icc = 0
        bl_sink = 0

    if local[0] > 0:
        local_icc = f"{local[2]} ({local[2]/local[0]*100:.2f}%)"
        local_sink =f"{local[3]} ({local[3]/local[0]*100:.2f}%)"
    else:
        local_icc = 0
        local_sink = 0

    if general[0] > 0:
        general_icc =f"{general[2]} ({general[2]/general[0]*100:.2f}%)"
        general_sink = f"{general[3]} ({general[3]/general[0]*100:.2f}%)"
    else:
        general_icc = 0
        general_sink = 0

    return [ bl_icc, bl_sink,bl[0], bl[1], local_icc, local_sink,  local[0],local[1], general_icc, general_sink,general[0], general[1]]

def format_row(df, total, row_name):
    result = []
    for row in df.iterrows():
        current_row = []
        print(row[0])
        for value in row[1].items():
            if row_name == row[0]:
                if value[0] == "apps":
                    current_row.append(f"{value[1]} ({value[1]/total * 100:.2f}%)")
                else:
                    current_row.append(value[1])
            else:
                current_row.append(value[1])
        result.append(current_row)

    return pd.DataFrame(result, index=df.index,columns =df.columns)

def write_to_file(data, filename):
    with open(filename, "w") as f:
        f.write(data)

if __name__=="__main__":
    path_bl_run_config = "config/bl_config.xml"
    icc_sinks = get_icc_sinks(path_bl_run_config)
    icc_sinks_methods = get_only_method_list(icc_sinks)

    general_local: List[FlowDroidRun] = parse_local_dataset("./docker/results")
    general_bl: List[FlowDroidRun] = parse_bl_dataset("./docker/results")
    general_general: List[FlowDroidRun] = parse_general_dataset("./docker/results")

    analyzed_gp_local = analyze_dataset(general_local)

    analyzed_gp_local = get_all_source_sink_connection(analyzed_gp_local)
    filtered_gp_local = filter_java_sinks(analyzed_gp_local)
    filtered_gp_local_2 = filter_local_dataset(filtered_gp_local)

    filtered_gp_local_3 = filter_local_dataset(filtered_gp_local_2, True)

    analyzed_gp_bl = analyze_dataset(general_bl)
    analyzed_gp_bl = get_all_source_sink_connection(analyzed_gp_bl)
    filtered_gp_bl = filter_java_sinks(analyzed_gp_bl)
    
    analyzed_gp_general = analyze_dataset(general_general)

    analyzed_gp_general = get_all_source_sink_connection(analyzed_gp_general)
    filtered_gp_general = filter_java_sinks(analyzed_gp_general)

    get_stats(filtered_gp_general)

    rows =[]
    # rows.append(create_row(get_stats(filtered_verified_bl), get_stats(filtered_verified_local_2), get_stats(filtered_verified_general )))
    rows.append(create_row(get_stats(filtered_gp_bl), get_stats(filtered_gp_local_2), get_stats(filtered_gp_general) ))

    df_flows = pd.DataFrame(rows, index=["IoT-abandonware"], columns=[ "ICC", "Endpoint","flows", "apps","ICC", "Endpoint","flows", "apps", "ICC", "Endpoint", "flows","apps"])
    row = df_flows.loc["IoT-abandonware"]

    with open("count_flows.txt", 'w') as f:
        for item in row.items():
            if item[0] == "apps":
                f.write(f'{item[0]}, {item[1]}\n')

    df_formatted = format_row(df_flows, app_num, "IoT-abandonware" )

    print(df_formatted.to_latex())

    without_icc_and_endpoints = df_formatted.drop(columns=['ICC', 'Endpoint'])
    print(without_icc_and_endpoints.to_latex())

    write_to_file(get_flows_with_source_sink_connection(filtered_gp_bl), "gp_bl.txt")
    write_to_file(get_flows_with_source_sink_connection(filtered_gp_local_2), "gp_local.txt")
    write_to_file(get_flows_with_source_sink_connection(filtered_gp_general), "gp_gen.txt")
