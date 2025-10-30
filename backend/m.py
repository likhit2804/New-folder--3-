import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import Adam
from torch_geometric.data import Data, HeteroData
from torch_geometric.nn import GATv2Conv, GCNConv, SAGEConv, GNNExplainer
from torch_geometric.nn import HypergraphConv # Placeholder
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
from sklearn.metrics.pairwise import cosine_similarity, euclidean_distances
from sklearn.preprocessing import StandardScaler

# ###########################################################################
# File: config.py
# ###########################################################################

# --- This is the main file you will edit to customize your architecture ---

# --- 1. General Settings ---
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
SEED = 42
NUM_EPOCHS = 100
LEARNING_RATE = 0.001
BATCH_SIZE = 32

# --- 2. Model Selection (YOUR KEY CUSTOMIZATION) ---
# Choose: 'baseline' or 'dual_gnn'
# 'baseline': Runs the simple MLP model from baseline_model.py
# 'dual_gnn': Runs the full GNN architecture from dual_gnn_model.py
MODEL_TYPE = 'baseline' 

# --- 3. Stage 1: Input & Feature Customization ---

# Define which omics data files to load
# This allows you to "choose which omics"
OMICS_FILES = {
    'gene_expression': 'data/gene_expression.csv',
    'mirna_expression': 'data/mirna_expression.csv',
    # 'methylation': 'data/methylation.csv', # Add/remove as needed
}

# Define which clinical features to use from the clinical file
CLINICAL_FILE = 'data/clinical_data.csv'
CLINICAL_FEATURES_TO_USE = [
    'ER_Status',
    'PR_Status',
    'HER2_Status',
    'PAM50_Subtype'
]

# Define pathway database file
PATHWAY_FILE = 'data/kegg_pathways.gmt' # Example: .gmt file format

# --- 4. Stage 2: Graph Construction Customization ---

# Settings for the Patient Similarity Network (PSN)
PSN_METRIC = 'cosine' # 'cosine', 'pearson', 'euclidean'
PSN_KNN_K = 10        # K-nearest neighbors to build the graph

# --- 5. Stage 3: Fusion & Classifier Customization ---

# "choosing between late and early fusion"
# 'late': (Default) Embeds from two branches are concatenated at the end.
# 'early': (Future) You would modify the model to combine graphs at the start.
FUSION_TYPE = 'late'

# Hidden dimensions for GNNs and MLPs
EMBEDDING_DIM = 64
HIDDEN_DIM = 128
MLP_HIDDEN_LAYERS = [128, 64]

# Number of attention heads for GAT models
NUM_HEADS = 4 

# --- 6. Stage 4: Explanation Settings ---
EXPLAINER_TYPE = 'GNNExplainer' # 'GNNExplainer', 'Captum'
NUM_BIOMARKERS_TO_FIND = 20


# ###########################################################################
# File: baseline_model.py
# ###########################################################################

class BaselineMLP(nn.Module):
    """
    This is the simplest possible baseline model, as requested.
    
    It completely ignores all graph structure (Stage 2) and 
    only uses the "Feature Vector" from Stage 1.
    
    It feeds this vector directly into a Multi-Layer Perceptron (MLP)
    to make a prediction.
    
    This is the model you must "beat" to justify using the complex GNN.
    """
    def __init__(self, input_dim, output_dim):
        super(BaselineMLP, self).__init__()
        
        layers = []
        layer_dims = [input_dim] + MLP_HIDDEN_LAYERS
        
        for i in range(len(layer_dims) - 1):
            layers.append(nn.Linear(layer_dims[i], layer_dims[i+1]))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(0.5))
            
        # Final output layer
        layers.append(nn.Linear(layer_dims[-1], output_dim))
        
        self.network = nn.Sequential(*layers)

    def forward(self, x):
        # x is the [batch_size, num_features] feature vector
        return self.network(x)


# ###########################################################################
# File: stage_1_data_loader.py
# ###########################################################################

def load_all_data():
    """
    Main function for Stage 1.
    Loads all data defined in the config file.
    """
    print("--- STAGE 1: Loading Data ---")
    
    # 1. Load Omics Data (Customizable by OMICS_FILES)
    omics_data_list = []
    for omic_name, file_path in OMICS_FILES.items():
        print(f"Loading omic: {omic_name} from {file_path}")
        # Assuming CSV with 'Patient_ID' as index and features as columns
        # In a real scenario, you'd add error handling (try-except)
        # try:
        #     data = pd.read_csv(file_path, index_col='Patient_ID')
        #     omics_data_list.append(data)
        # except FileNotFoundError:
        #     print(f"Warning: File not found {file_path}. Skipping.")
        pass # Placeholder logic
        
    # Placeholder data if files don't exist
    if not omics_data_list:
        print("Using placeholder omics data")
        omics_data = pd.DataFrame(np.random.rand(100, 500), 
                                  columns=[f'gene_{i}' for i in range(500)],
                                  index=[f'patient_{i}' for i in range(100)])
    else:
        omics_data = pd.concat(omics_data_list, axis=1) # Combine all omics

    # 2. Load Clinical Data (Customizable by CLINICAL_FEATURES_TO_USE)
    print(f"Loading clinical data from {CLINICAL_FILE}")
    # try:
    #     clinical_data_all = pd.read_csv(CLINICAL_FILE, index_col='Patient_ID')
    #     clinical_data = clinical_data_all[CLINICAL_FEATURES_TO_USE]
    # except FileNotFoundError:
    #     print("Warning: Clinical file not found. Using placeholder data.")
    clinical_data = pd.DataFrame({
        'ER_Status': np.random.randint(0, 2, 100),
        'PR_Status': np.random.randint(0, 2, 100),
        'HER2_Status': np.random.randint(0, 2, 100),
        'PAM50_Subtype': np.random.randint(0, 2, 100)
    }, index=[f'patient_{i}' for i in range(100)])
    
    # One-hot encode categorical clinical features
    clinical_data_encoded = pd.get_dummies(clinical_data, 
                                           columns=['ER_Status', 'PR_Status', 'HER2_Status'])

    # 3. Create the "Feature Vector" (for Baseline and PSN)
    # This combines selected omics (e.g., PAM50 genes) and clinical data
    # For simplicity, we'll just use the encoded clinical data + all omics for now
    feature_vector = pd.concat([omics_data, clinical_data_encoded], axis=1)
    
    # 4. Load Pathway DB
    print(f"Loading pathway data from {PATHWAY_FILE}")
    # pathway_db = load_gmt_file(PATHWAY_FILE)
    # Placeholder
    pathway_db = {
        'pathway_1': ['gene_0', 'gene_1', 'gene_10'],
        'pathway_2': ['gene_5', 'gene_10', 'gene_20', 'gene_30'],
    }
    
    # 5. Load Labels (e.g., Subtype Prediction)
    # labels = clinical_data['Subtype_Label'] # Your target variable
    labels = pd.Series(np.random.randint(0, 4, 100), index=[f'patient_{i}' for i in range(100)])
    num_classes = len(labels.unique())

    print(f"Data loading complete. Feature vector shape: {feature_vector.shape}")
    
    return omics_data, feature_vector, pathway_db, labels, num_classes

def load_gmt_file(gmt_path):
    """Helper to parse a .gmt pathway file."""
    pathways = {}
    try:
        with open(gmt_path, 'r') as f:
            for line in f:
                parts = line.strip().split('\t')
                pathway_name = parts[0]
                genes = parts[2:]
                pathways[pathway_name] = genes
    except FileNotFoundError:
        print(f"Warning: GMT file not found: {gmt_path}. Returning empty pathway DB.")
        return {}
    return pathways


# ###########################################################################
# File: stage_2_graph_construction.py
# ###########################################################################

def build_patient_similarity_network(feature_vector):
    """
    Builds the Patient Similarity Network (PSN) for Stage 2.
    
    WHY: This graph models patient-patient relationships. The GNN
    will learn by "passing messages" between similar patients,
    allowing it to learn group-level patterns, not just
    individual patient features.
    
    Customizable by: PSN_METRIC, PSN_KNN_K
    """
    print(f"--- STAGE 2: Building Patient Similarity Network (PSN) ---")
    print(f"Metric: {PSN_METRIC}, K-Nearest-Neighbors: {PSN_KNN_K}")

    # 1. Normalize features before similarity calculation
    features_scaled = StandardScaler().fit_transform(feature_vector)
    
    # 2. Calculate similarity matrix (Customizable)
    if PSN_METRIC == 'cosine':
        sim_matrix = cosine_similarity(features_scaled)
    elif PSN_METRIC == 'euclidean':
        dist_matrix = euclidean_distances(features_scaled)
        sim_matrix = 1.0 / (1.0 + dist_matrix) # Convert distance to similarity
    else:
        raise ValueError(f"Unknown PSN_METRIC: {PSN_METRIC}")
        
    np.fill_diagonal(sim_matrix, 0) # Remove self-loops

    # 3. Create graph edges using K-Nearest-Neighbors
    edge_index = []
    num_patients = sim_matrix.shape[0]
    
    for i in range(num_patients):
        # Get top K neighbors for patient i
        top_k_indices = np.argsort(sim_matrix[i, :])[-PSN_KNN_K:]
        for j in top_k_indices:
            if sim_matrix[i, j] > 0: # Only add edge if similarity > 0
                edge_index.append([i, j])
                
    edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    
    # 4. Create PyTorch Geometric Data object
    x = torch.tensor(features_scaled, dtype=torch.float)
    psn_graph = Data(x=x, edge_index=edge_index_tensor)
    
    print(f"PSN graph built: {psn_graph}")
    return psn_graph


def build_pathway_hypergraph(omics_data, pathway_db):
    """
    Builds the Pathway Hypergraph for Stage 2.
    
    WHY: A normal graph (gene-gene) can't model pathways
    (which are sets of genes). A hypergraph creates a "hyperedge"
    for each pathway, connecting all genes in that pathway.
    This is a more accurate biological representation.
    
    This function creates the hypergraph incidence matrix.
    """
    print(f"--- STAGE 2: Building Pathway Hypergraph ---")
    
    # Map gene names to indices
    all_genes = list(omics_data.columns)
    gene_to_idx = {gene: i for i, gene in enumerate(all_genes)}
    num_genes = len(all_genes)
    num_pathways = len(pathway_db)
    
    print(f"Found {num_genes} genes/omics and {num_pathways} pathways.")

    # Create a hypergraph incidence matrix (H)
    # H is (Num_Genes x Num_Pathways)
    # H[i, j] = 1 if gene i is in pathway j
    
    # This is a placeholder. A real hypergraph GNN library
    # might take this in a different format (e.g., edge list)
    incidence_matrix = torch.zeros((num_genes, num_pathways), dtype=torch.float)
    
    for j, (pathway_name, genes_in_pathway) in enumerate(pathway_db.items()):
        for gene in genes_in_pathway:
            if gene in gene_to_idx:
                i = gene_to_idx[gene]
                incidence_matrix[i, j] = 1.0

    # For PyG, a hypergraph is often represented by its 'hyperedge_index'
    # which is a [2, num_connections] tensor
    # Row 0: node (gene) indices
    # Row 1: hyperedge (pathway) indices
    
    hyperedge_index_list = []
    for j, (pathway_name, genes_in_pathway) in enumerate(pathway_db.items()):
        for gene in genes_in_pathway:
            if gene in gene_to_idx:
                i = gene_to_idx[gene]
                hyperedge_index_list.append([i, j])
                
    if not hyperedge_index_list:
        print("Warning: No matching genes found in pathways. Using placeholder hypergraph.")
        # Create a dummy hyperedge
        hyperedge_index_tensor = torch.tensor([[0, 1], [0, 0]], dtype=torch.long)
    else:
        hyperedge_index_tensor = torch.tensor(hyperedge_index_list, dtype=torch.long).t().contiguous()

    # Create a PyG HeteroData object to represent the bipartite graph
    # This is how PyG can model hypergraphs
    hypergraph = HeteroData()
    hypergraph['gene'].x = torch.tensor(omics_data.values, dtype=torch.float) # [Num_Patients, Num_Genes]
    hypergraph['pathway'].num_nodes = num_pathways
    
    hypergraph['gene', 'in', 'pathway'].edge_index = hyperedge_index_tensor
    
    print(f"Hypergraph built: {hypergraph}")
    return hypergraph


# ###########################################################################
# File: stage_2_models.py
# ###########################################################################

# --- Model for Patient Network (PSN) ---
class PatientGNN(nn.Module):
    """
    This is the GNN for the Patient Similarity Network (PSN).
    
    WHY: It takes the PSN graph and learns an "embedding" for each
    patient by looking at their features and their neighbors' features.
    
    Customizable by: config.GNN_TYPE (e.g., GAT, GCN)
    """
    def __init__(self, input_dim, output_dim):
        super(PatientGNN, self).__init__()
        
        self.conv1 = GATv2Conv(input_dim, HIDDEN_DIM, 
                               heads=NUM_HEADS)
        
        # Output embedding dim is HIDDEN_DIM * NUM_HEADS
        self.conv2 = GATv2Conv(HIDDEN_DIM * NUM_HEADS, 
                               output_dim, 
                               heads=1, concat=False)

    def forward(self, data):
        # data is a PyG Data object (x, edge_index)
        x, edge_index = data.x, data.edge_index
        
        x = F.dropout(x, p=0.6, training=self.training)
        x = F.elu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.6, training=self.training)
        x = self.conv2(x, edge_index) # Final patient embeddings
        
        return x

# --- Model for Biological Network (Hypergraph) ---
class BiologyHyperGNN(nn.Module):
    """
    This is the GNN for the Pathway Hypergraph.
    
    WHY: It learns an embedding for genes/miRNAs based on which
    pathways (hyperedges) they belong to.
    
    This is a placeholder, as HyperGNNs are complex. A common
    way to implement them is to use a standard GNN on a
    bipartite representation (gene nodes <-> pathway nodes).
    
    We will use a simple GNN on the bipartite graph for this example.
    """
    def __init__(self, gene_input_dim, pathway_input_dim, output_dim):
        super(BiologyHyperGNN, self).__init__()
        
        # This is a placeholder for a true HyperGAT or similar model
        # For simplicity, we can't implement a full HyperGAT here.
        # We will use a simple pass-through embedding as a placeholder.
        
        print("NOTE: BiologyHyperGNN is a placeholder. "
              "A real implementation (e.g., HyperGAT) is complex.")
        
        # Placeholder: A simple Linear embedding for gene features
        # A real model would use the hypergraph.edge_index
        self.gene_embedder = nn.Linear(gene_input_dim, output_dim)

    def forward(self, data):
        # data is a PyG HeteroData object
        # Gene features are [Num_Patients, Num_Genes]
        # We need to learn embeddings for genes/pathways
        
        # This is a simplified placeholder
        # A real model would do message passing
        gene_x = data['gene'].x
        
        # We are simplifying greatly. Let's assume we learn a
        # single embedding vector for all genes for now.
        # A true implementation is much more complex.
        
        # Placeholder: just mean-pool the patient-specific gene features
        # to get a [1, Num_Genes] vector and embed that.
        gene_features_mean = torch.mean(gene_x, dim=0) # [Num_Genes]
        
        # This logic is flawed but demonstrates the *location*
        # where the hypergraph GNN would go.
        # Let's just return a placeholder tensor.
        
        # Correct placeholder: learn an embedding for each *patient*
        # based on their *gene expression profile*
        
        # Input gene_x is [Num_Patients, Num_Genes]
        # We want patient-specific gene embeddings
        
        # This model will just be an MLP on the gene expression
        # data for each patient.
        
        patient_gene_embeddings = self.gene_embedder(gene_x) # [Num_Patients, output_dim]
        
        return patient_gene_embeddings


# ###########################################################################
# File: dual_gnn_model.py
# ###########################################################################

class DualBranchGNN(nn.Module):
    """
    This is the main model from your flowchart (Stages 2 & 3).
    
    It combines the two branches:
    1. BiologyHyperGNN (Top Branch)
    2. PatientGNN (Bottom Branch)
    
    It then fuses their outputs (Late Fusion) and passes them
    to a final MLP classifier.
    
    Customizable by: FUSION_TYPE
    """
    def __init__(self, 
                 patient_feat_dim, 
                 gene_feat_dim, 
                 pathway_feat_dim,
                 num_classes):
        super(DualBranchGNN, self).__init__()
        
        self.fusion_type = FUSION_TYPE
        
        # --- 1. Instantiate the Two GNN Branches ---
        
        # Branch 1: Biological Network
        # Input: Gene expression [Num_Patients, Num_Genes]
        # Output: Patient-specific gene embeddings [Num_Patients, EMBEDDING_DIM]
        self.bio_gnn = BiologyHyperGNN(gene_feat_dim, 
                                       pathway_feat_dim, 
                                       EMBEDDING_DIM)
        
        # Branch 2: Patient Network
        # Input: Patient features [Num_Patients, Num_Features]
        # Output: Patient graph embeddings [Num_Patients, EMBEDDING_DIM]
        self.patient_gnn = PatientGNN(patient_feat_dim, 
                                      EMBEDDING_DIM)
        
        
        # --- 2. Instantiate the Fusion & Classifier (Stage 3) ---
        
        if self.fusion_type == 'late':
            # Late Fusion: Concatenate the embeddings from both branches
            # Total embedding size = 2 * EMBEDDING_DIM
            classifier_input_dim = EMBEDDING_DIM * 2
            
            layers = []
            layer_dims = [classifier_input_dim] + MLP_HIDDEN_LAYERS
            
            for i in range(len(layer_dims) - 1):
                layers.append(nn.Linear(layer_dims[i], layer_dims[i+1]))
                layers.append(nn.ReLU())
                layers.append(nn.Dropout(0.5))
            
            layers.append(nn.Linear(layer_dims[-1], num_classes))
            self.classifier = nn.Sequential(*layers)
            
        elif self.fusion_type == 'early':
            # Early fusion would mean building one giant graph
            # The model architecture would be different
            raise NotImplementedError("Early fusion not yet implemented.")
        
        else:
            raise ValueError(f"Unknown FUSION_TYPE: {self.fusion_type}")

    def forward(self, patient_graph_data, biological_graph_data):
        """
        The main forward pass of the model.
        """
        
        # 1. Run the Biological Network branch
        # This gets the "miRNA/Gene Embeds" per patient
        # [Num_Patients, EMBEDDING_DIM]
        bio_embeddings = self.bio_gnn(biological_graph_data)
        
        # 2. Run the Patient Network branch
        # This gets the "Patient Embeds"
        # [Num_Patients, EMBEDDING_DIM]
        patient_embeddings = self.patient_gnn(patient_graph_data)
        
        # 3. (Stage 3) Fuse the embeddings
        if self.fusion_type == 'late':
            # [Num_Patients, EMBEDDING_DIM * 2]
            fused_embeddings = torch.cat([bio_embeddings, patient_embeddings], dim=1)
            
            # 4. (Stage 3) Run the final classifier
            # [Num_Patients, num_classes]
            logits = self.classifier(fused_embeddings)
            return logits
        
        else:
            # Handle other fusion types
            pass


# ###########################################################################
# File: stage_4_explain.py
# ###########################################################################

def explain_model(model, graph_data, patient_idx_to_explain):
    """
    Main function for Stage 4.
    Runs an explainer to find important features/nodes.
    
    WHY: This is for finding biomarkers.
    - "In-Hoc": Would involve pulling attention weights directly
      from the GATv2Conv layers in the model.
    - "Post-Hoc": Uses an explainer like GNNExplainer *after*
      training to find the most important parts of the graph.
      
    Customizable by: EXPLAINER_TYPE
    """
    print(f"--- STAGE 4: Running Explainer ({EXPLAINER_TYPE}) ---")
    
    if EXPLAINER_TYPE == 'GNNExplainer':
        # GNNExplainer needs to be attached to a model
        # We will explain the PatientGNN branch
        
        # NOTE: Explaining the full DualBranchGNN is complex.
        # We'll start by explaining just one branch (PatientGNN).
        
        explainer = GNNExplainer(
            epochs=200, 
            lr=0.01, 
            return_type='log_prob',
            model_config=dict(
                mode='classification',
                task_level='node',
                return_type='log_prob',
            ),
        )
        
        # Get the PatientGNN part of the full model
        patient_gnn = model.patient_gnn
        node_feat_mask, edge_mask = explainer.explain_node(
            patient_idx_to_explain, 
            graph_data.x, 
            graph_data.edge_index
        )
        
        print(f"Top {NUM_BIOMARKERS_TO_FIND} important features (from feature mask):")
        top_feature_indices = torch.topk(node_feat_mask, NUM_BIOMARKERS_TO_FIND).indices
        
        # You would map these indices back to your feature_vector column names
        # e.g., biomarker_names = feature_vector.columns[top_feature_indices]
        # print(biomarker_names)
        
        return top_feature_indices, edge_mask

    elif EXPLAINER_TYPE == 'Attention':
        print("Extracting In-Hoc Attention Weights...")
        # This would involve custom hooks to grab the 'alpha'
        # variable from the GATv2Conv layers during the forward pass.
        # This is an advanced technique.
        pass
    
    else:
        print(f"Explainer type {EXPLAINER_TYPE} not implemented.")


# ###########################################################################
# File: main.py
# ###########################################################################

def train(model, data, optimizer, criterion):
    """Helper function for a single training epoch."""
    model.train()
    optimizer.zero_grad()
    
    # --- This logic changes based on the model type ---
    if MODEL_TYPE == 'baseline':
        # Baseline model only takes the feature vector (x)
        logits = model(data['x_tensor'])
        labels = data['labels_tensor']
        train_mask = data['train_mask']
        loss = criterion(logits[train_mask], labels[train_mask])
        
    elif MODEL_TYPE == 'dual_gnn':
        # Full GNN model takes both graphs
        logits = model(data['psn_graph'], data['hypergraph'])
        labels = data['labels_tensor']
        train_mask = data['train_mask']
        loss = criterion(logits[train_mask], labels[train_mask])
    
    loss.backward()
    optimizer.step()
    return loss.item()

def evaluate(model, data):
    """Helper function to evaluate the model."""
    model.eval()
    with torch.no_grad():
        if MODEL_TYPE == 'baseline':
            logits = model(data['x_tensor'])
        elif MODEL_TYPE == 'dual_gnn':
            logits = model(data['psn_graph'], data['hypergraph'])
        
        labels = data['labels_tensor']
        val_mask = data['val_mask']
        test_mask = data['test_mask']
        
        preds = logits.argmax(dim=1)
        
        val_acc = accuracy_score(labels[val_mask].cpu(), preds[val_mask].cpu())
        test_acc = accuracy_score(labels[test_mask].cpu(), preds[test_mask].cpu())
        
        val_f1 = f1_score(labels[val_mask].cpu(), preds[val_mask].cpu(), average='weighted')
        test_f1 = f1_score(labels[test_mask].cpu(), preds[test_mask].cpu(), average='weighted')
        
        return val_acc, test_acc, val_f1, test_f1

def main():
    """
    The main script that ties everything together.
    
    1. Loads config
    2. Loads data (Stage 1)
    3. Builds graphs (Stage 2)
    4. Selects, builds, and trains the model (Baseline or GNN)
    5. Evaluates the model
    6. Explains the model (Stage 4)
    """
    
    print(f"--- Starting Run ---")
    print(f"Using device: {DEVICE}")
    print(f"Selected model type: {MODEL_TYPE}")
    
    # Set random seed for reproducibility
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    if DEVICE == 'cuda':
        torch.cuda.manual_seed(SEED)

    # --- STAGE 1: LOAD DATA ---
    omics_data, feature_vector, pathway_db, labels, num_classes = \
        load_all_data()

    # --- Create Data Splits ---
    num_patients = len(labels)
    indices = np.arange(num_patients)
    
    train_indices, test_indices = train_test_split(indices, test_size=0.2, random_state=SEED)
    train_indices, val_indices = train_test_split(train_indices, test_size=0.15, random_state=SEED) # 0.15 * 0.8 = 0.12

    train_mask = torch.zeros(num_patients, dtype=torch.bool)
    val_mask = torch.zeros(num_patients, dtype=torch.bool)
    test_mask = torch.zeros(num_patients, dtype=torch.bool)
    
    train_mask[train_indices] = True
    val_mask[val_indices] = True
    test_mask[test_indices] = True
    
    labels_tensor = torch.tensor(labels.values, dtype=torch.long).to(DEVICE)
    
    # --- Initialize Model, Data, and Optimizer based on Config ---
    
    model = None
    optimizer = None
    training_data_package = {} # To pass to train/eval functions
    
    if MODEL_TYPE == 'baseline':
        # --- Baseline Model Path ---
        print("Initializing BaselineMLP Model")
        x_tensor = torch.tensor(feature_vector.values, dtype=torch.float).to(DEVICE)
        
        model = BaselineMLP(
            input_dim=feature_vector.shape[1],
            output_dim=num_classes
        ).to(DEVICE)
        
        training_data_package = {
            'x_tensor': x_tensor,
            'labels_tensor': labels_tensor,
            'train_mask': train_mask,
            'val_mask': val_mask,
            'test_mask': test_mask
        }

    elif MODEL_TYPE == 'dual_gnn':
        # --- Full GNN Model Path ---
        print("Initializing DualBranchGNN Model")
        
        # --- STAGE 2: BUILD GRAPHS ---
        psn_graph = build_patient_similarity_network(
            feature_vector
        ).to(DEVICE)
        
        hypergraph = build_pathway_hypergraph(
            omics_data, pathway_db
        ).to(DEVICE)
        
        model = DualBranchGNN(
            patient_feat_dim=psn_graph.num_node_features,
            gene_feat_dim=omics_data.shape[1],
            pathway_feat_dim=len(pathway_db), # Placeholder
            num_classes=num_classes
        ).to(DEVICE)
        
        training_data_package = {
            'psn_graph': psn_graph,
            'hypergraph': hypergraph,
            'labels_tensor': labels_tensor,
            'train_mask': train_mask,
            'val_mask': val_mask,
            'test_mask': test_mask
        }

    else:
        raise ValueError(f"Unknown MODEL_TYPE in config: {MODEL_TYPE}")

    # --- Common Training Setup ---
    optimizer = Adam(model.parameters(), lr=LEARNING_RATE)
    criterion = torch.nn.CrossEntropyLoss()
    
    print("\n--- STAGE 3: Starting Model Training ---")
    best_val_acc = 0
    best_epoch = 0
    
    for epoch in range(1, NUM_EPOCHS + 1):
        loss = train(model, training_data_package, optimizer, criterion)
        val_acc, _, val_f1, _ = evaluate(model, training_data_package)
        
        if epoch % 10 == 0:
            print(f"Epoch: {epoch:03d}, Loss: {loss:.4f}, Val Acc: {val_acc:.4f}, Val F1: {val_f1:.4f}")
            
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_epoch = epoch
            # Save the best model state
            torch.save(model.state_dict(), f'{MODEL_TYPE}_best_model.pth')

    print("--- Training Finished ---")
    print(f"Best Validation Accuracy: {best_val_acc:.4f} at Epoch {best_epoch}")
    
    # --- Load best model and evaluate on Test set ---
    model.load_state_dict(torch.load(f'{MODEL_TYPE}_best_model.pth'))
    _, test_acc, _, test_f1 = evaluate(model, training_data_package)
    
    print(f"\n--- Final Test Set Performance ---")
    print(f"Test Accuracy: {test_acc:.4f}")
    print(f"Test F1-Score: {test_f1:.4f}")

    # --- STAGE 4: EXPLAIN MODEL ---
    if MODEL_TYPE == 'dual_gnn':
        # Pick a patient from the test set to explain
        patient_to_explain = test_indices[0]
        explain_model(
            model, 
            training_data_package['psn_graph'], 
            patient_to_explain
        )

if __name__ == "__main__":
    # This check ensures that the main() function runs only
    # when you execute this file directly, e.g., "python dual_gnn_project.py"
    main()
