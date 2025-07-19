import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report


class Classifier(nn.Module):
    def __init__(self, input_dim, num_classes):
        super(Classifier, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),

            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),

            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3),

            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(32, num_classes)
        )

    def forward(self, x):
        return self.model(x)

from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

def train_classifier(model, X, y, epochs=50, batch_size=256, lr=1e-3):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    train_ds = TensorDataset(torch.tensor(X_train, dtype=torch.float32), torch.tensor(y_train, dtype=torch.long))
    val_ds = TensorDataset(torch.tensor(X_val, dtype=torch.float32), torch.tensor(y_val, dtype=torch.long))

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size)

    class_weights = compute_class_weight(class_weight='balanced', classes=np.unique(y), y=y)
    class_weights_tensor = torch.tensor(class_weights, dtype=torch.float32).to(device)

    criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    history = {
        "train_loss": [],
        "val_loss": [],
        "train_acc": [],
        "val_acc": [],
        "val_precision": [],
        "val_recall": [],
        "val_f1": []
    }

    for epoch in range(epochs):
        model.train()
        total_loss = 0
        correct, total = 0, 0

        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            preds = model(xb)
            loss = criterion(preds, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * yb.size(0)
            correct += (preds.argmax(1) == yb).sum().item()
            total += yb.size(0)

        train_loss = total_loss / total
        train_accuracy = correct / total

        # Validation
        model.eval()
        val_loss = 0
        val_correct, val_total = 0, 0
        all_preds, all_labels = [], []

        with torch.no_grad():
            for xb, yb in val_loader:
                xb, yb = xb.to(device), yb.to(device)
                preds = model(xb)
                loss = criterion(preds, yb)

                val_loss += loss.item() * yb.size(0)
                val_correct += (preds.argmax(1) == yb).sum().item()
                val_total += yb.size(0)

                all_preds.extend(preds.argmax(1).cpu().numpy())
                all_labels.extend(yb.cpu().numpy())

        val_loss /= val_total
        val_accuracy = val_correct / val_total
        val_precision = precision_score(all_labels, all_preds, average='macro', zero_division=0)
        val_recall = recall_score(all_labels, all_preds, average='macro', zero_division=0)
        val_f1 = f1_score(all_labels, all_preds, average='macro', zero_division=0)

        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        history["train_acc"].append(train_accuracy)
        history["val_acc"].append(val_accuracy)
        history["val_precision"].append(val_precision)
        history["val_recall"].append(val_recall)
        history["val_f1"].append(val_f1)

        if epoch % 10 == 0 or epoch == epochs - 1:
            print(f"Epoch {epoch+1}/{epochs} | "
                  f"Train Acc: {train_accuracy:.4f} | Val Acc: {val_accuracy:.4f} | "
                  f"Val F1: {val_f1:.4f}")

    # Confusion matrix finale
    print("\n📊 Final validation confusion matrix:")
    conf_matrix = confusion_matrix(all_labels, all_preds)
    print(conf_matrix)

    # Classification report
    print("\n📄 Final classification report (per class):")
    report = classification_report(all_labels, all_preds, digits=4, zero_division=0)
    print(report)

    return model, history


def export_classifier_to_onnx(model, X_sample, path="models/classifier.onnx"):
    model.eval()
    exportable = ExportableClassifier(model)

    example_input = torch.tensor(X_sample[:1], dtype=torch.float32)

    sample = torch.tensor(X_sample[:1], dtype=torch.float32)
    print("Raw logits:", model(sample))
    print("Softmax:", nn.Softmax(dim=1)(model(sample)))
    torch.onnx.export(
        exportable,
        example_input,
        path,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
        opset_version=11
    )
    print(f"✅ Classificatore esportato in ONNX: {path}")


class ExportableClassifier(nn.Module):
    def __init__(self, trained_model):
        super().__init__()
        self.model = trained_model.model  # Usa solo la rete interna
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        return self.softmax(self.model(x))
    


def plot_training_metrics(history):
    epochs = range(1, len(history["train_loss"]) + 1)

    # 1. Loss
    plt.figure(figsize=(10, 4))
    plt.plot(epochs, history["train_loss"], label="Train Loss")
    plt.plot(epochs, history["val_loss"], label="Validation Loss")
    plt.xlabel("Epochs")
    plt.ylabel("Loss")
    plt.title("Loss per Epoch")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # 2. Accuracy
    plt.figure(figsize=(10, 4))
    plt.plot(epochs, history["train_acc"], label="Train Accuracy")
    plt.plot(epochs, history["val_acc"], label="Validation Accuracy")
    plt.xlabel("Epochs")
    plt.ylabel("Accuracy")
    plt.title("Accuracy per Epoch")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # 3. Precision
    plt.figure(figsize=(10, 4))
    plt.plot(epochs, history["val_precision"], label="Validation Precision")
    plt.xlabel("Epochs")
    plt.ylabel("Precision (Macro)")
    plt.title("Validation Precision per Epoch")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # 4. Recall
    plt.figure(figsize=(10, 4))
    plt.plot(epochs, history["val_recall"], label="Validation Recall")
    plt.xlabel("Epochs")
    plt.ylabel("Recall (Macro)")
    plt.title("Validation Recall per Epoch")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # 5. F1 Score
    plt.figure(figsize=(10, 4))
    plt.plot(epochs, history["val_f1"], label="Validation F1 Score")
    plt.xlabel("Epochs")
    plt.ylabel("F1 Score (Macro)")
    plt.title("Validation F1 Score per Epoch")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()