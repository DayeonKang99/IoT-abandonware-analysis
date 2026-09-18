import json
import os
import re
import pathlib

# Configuration
result_dir = './results/'
output_file = './vsa-crypto-analysis-result.json'


def cluster_algorithm(algorithm):
    """Ported from Encryption copy.ipynb: Normalizes algorithm names."""
    if not algorithm:
        return None
    algorithm = algorithm.lower()
    if algorithm.startswith('aes'): return 'AES'
    elif algorithm in ['arc4', 'arcfour', 'rc4']: return 'RC4'
    elif algorithm == 'blowfish': return 'BLOWFISH'
    elif algorithm.startswith('cast'): return "CAST"
    elif algorithm.startswith('chacha'): return "ChaCha"
    elif algorithm.startswith('des'):
        if algorithm == "desede3": return "DES3"
        elif algorithm == "desede": return "DES2"
        return "DES"
    elif algorithm in ["dh", "ecdh"]: return "DH"
    elif algorithm.startswith('grain'): return "GRAIN"
    elif algorithm.startswith('gost'): return "GOST"
    elif algorithm.startswith('hc'): return "HC"
    elif algorithm.startswith('hmac'): return "HMAC"
    elif algorithm.startswith('md5'): return "MD5"
    elif algorithm.startswith('noekeon'): return "Noekeon"
    elif algorithm.startswith('pbe'): return "PBE"
    elif algorithm.startswith('pbkdf'): return "PBKDF"
    elif algorithm.startswith('poly'): return "ChaCha"
    elif algorithm == 'rc2': return "RC2"
    elif algorithm == 'rc5': return "RC5"
    elif algorithm == 'rc6': return "RC6"
    elif algorithm.startswith('rsa'): return "RSA"
    elif algorithm.startswith('hkdf'): return "HKDF"
    elif algorithm.startswith('zuc'): return "ZUC"
    elif algorithm.startswith('twofish'): return "Twofish"
    elif algorithm.startswith('tnepres'): return "Tnepres"
    elif algorithm.startswith('threefish'): return "Threefish"
    elif algorithm.startswith('skipjack'): return "Skipjack"
    elif algorithm.startswith('skein'): return "Skein"
    elif algorithm.startswith('shacal'): return "Shacal"
    elif algorithm.startswith('serpent'): return "Serpent"
    elif algorithm.startswith('salsa'): return "Salsa"
    elif algorithm.startswith('sha1'): return "SHA1"
    elif algorithm.startswith('sha'): return "SHA"
    elif algorithm.startswith('scrypt'): return "SCRYPT"
    elif algorithm.startswith('rijndael'): return "Rijndael"
    return None

def is_valid_sanitized(algorithm):
    """Ported logic from sanitize_algorithm in the notebook."""
    if not algorithm or len(algorithm) < 2: return False
    forbidden = ['.', 'unknown', '$', '{}', 'lgorithm', 'UNKNOWN', '@', 'Alg', 'helper', 
                 'aaa', 'value', 'zz', '_a', '_enve', '5gaj', 'AUTHORITY', 'BASIC_CONS', '00', '0o', 'ame']
    for term in forbidden:
        if term in algorithm: return False
    return True

def get_all_values_from_valueset(value_sets, index_id):
    """Extracts values from the specific index in the ValueSet list."""
    result = set()
    for vs in value_sets:
        data = vs.get(str(index_id), [])
        for d in data:
            result.add(d)
    return result

def extract_algorithms_from_data(data):
    """Logic derived from extract_algorithm_from_json in the notebook."""
    algorithms = set()
    
    for vp in data.get("ValuePoints", []):
        signature = vp.get("appendix", {}).get("sigatureInApp", "")
        if not signature:
            continue
            
        values = set()
        # Logic: Extract from specific index based on the Java signature
        if "javax.crypto.spec.SecretKeySpec: void <init>(byte[],int,int,java.lang.String)" in signature:
            values = get_all_values_from_valueset(vp.get("ValueSet", []), 3)
        elif "javax.crypto.spec.SecretKeySpec: void <init>(byte[],java.lang.String)" in signature:
            values = get_all_values_from_valueset(vp.get("ValueSet", []), 1)
        elif "javax.security.auth.kerberos.KerberosKey: void <init>(javax.security.auth.kerberos.KerberosPrincipal,char[],java.lang.String)" in signature:
            values = get_all_values_from_valueset(vp.get("ValueSet", []), 2)
        elif any(s in signature for s in ["DESedeKeySpec", "DESKeySpec"]):
            values.add("DES")
        elif "DHPrivateKeySpec" in signature:
            values.add("DH")
        elif "DSAPrivateKeySpec" in signature:
            values.add("DSA")
        elif "ECPrivateKeySpec" in signature:
            values.add("EC")
        elif any(s in signature for s in ["RSAPrivateKeySpec", "RSAMultiPrimePrivateCrtKeySpec"]):
            values.add("RSA")

        # Sanitize and Cluster
        for v in values:
            if is_valid_sanitized(v):
                clustered = cluster_algorithm(v)
                if clustered:
                    algorithms.add(clustered)
                    
    return sorted(list(algorithms))

def get_json_files(directory_path):
    path = pathlib.Path(directory_path)
    return [item for item in path.rglob('*.json') if item.is_file()]

if __name__ == '__main__':
    results = {"apps": []}
    crypto_path = os.path.join(result_dir, "crypto")
    
    json_files = get_json_files(crypto_path)
    
    if not json_files:
        print(f"⚠️ No JSON files found in {crypto_path}")
    
    for file_path in json_files:
        app_name = file_path.stem
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            found_algs = extract_algorithms_from_data(data)
            
            results["apps"].append({
                "app_name": app_name,
                "encryption_algs": found_algs,
            })
        except Exception as e:
            print(f"❌ Error processing {app_name}: {e}")

    # Create directory if not exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
        
    print(f"✅ Analyzing VSA encryption algorithm finished. Results saved to {output_file}")