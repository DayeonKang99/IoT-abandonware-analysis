# IoT-Abandonware

We present the security analysis framework for abandoned IoT companion apps. 
The dataset we used is in `/dataset` directory and codes for analysis are in `/src`

## Configuring IoT Abandonware Dataset

---
## Embedded Resource Analysis

### Outdated Dependencies Analysis

### At-Risk Domain Analysis

### IoTFlow
Clone IoTFlow repository under the `src/iotflow/` folder.

```bash
git clone https://github.com/SecPriv/iotflow.git
cp flowanalysis.py FlowAnalysis/docker/
cp vsa_analysis.py VSA/docker/
```

#### Data Flow Analysis
1. `cd FlowAnalysis/docker`
2. Add `apk` files to the folder `apps_to_analyze/`
3. `docker compose up`
4. Results will be placed into `results/`
5. Run flow analysis script `python flowanalysis.py`
6. Copy the analysis script output to `/src/iotflow/plot-codes`
7. You can draw the plot with `plot-flowanalysis.ipynb`

#### Cryptographic Analysis
1. `cd VSA/docker`
2. Add `apk` files to the folder `apps_to_analyze/`
3. `docker compose up`
4. Results will be placed into `results/`
5. Run cryptographic analysis script `python vsa_analysis.py`
6. Copy the analysis script output to `/src/iotflow/plot-codes`
7. You can draw the plot with `plot-vsa-analysis.ipynb`