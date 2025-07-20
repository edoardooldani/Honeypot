from preprocessing import normalize_column_name, rename
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split


class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(64, 32),
            nn.ReLU(),

            nn.Linear(32, 16),
            nn.ReLU(),

            nn.Linear(16, 8),
            nn.ReLU()
        )

        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),

            nn.Linear(16, 32),
            nn.ReLU(),

            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(128, input_dim),
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def train_autoencoder(model, X, epochs=100, batch_size=256, patience=10, learning_rate=1e-3):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    # 👉 Split train/val
    X_train, X_val = train_test_split(X, test_size=0.2, random_state=42)

    # Dataset e dataloader
    train_tensor = torch.tensor(X_train.astype('float32'))
    val_tensor = torch.tensor(X_val.astype('float32'))
    train_loader = DataLoader(TensorDataset(train_tensor), batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(TensorDataset(val_tensor), batch_size=batch_size)

    criterion = nn.L1Loss()
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)

    best_val_loss = float('inf')
    patience_counter = 0
    train_loss_history = []
    val_loss_history = []

    for epoch in range(epochs):
        # === Training ===
        model.train()
        total_train_loss = 0
        for batch in train_loader:
            x = batch[0].to(device)
            optimizer.zero_grad()
            outputs = model(x)
            loss = criterion(outputs, x)
            loss.backward()
            optimizer.step()
            total_train_loss += loss.item() * x.size(0)

        avg_train_loss = total_train_loss / len(train_loader.dataset)
        train_loss_history.append(avg_train_loss)

        # === Validation ===
        model.eval()
        total_val_loss = 0
        with torch.no_grad():
            for batch in val_loader:
                x = batch[0].to(device)
                outputs = model(x)
                loss = criterion(outputs, x)
                total_val_loss += loss.item() * x.size(0)

        avg_val_loss = total_val_loss / len(val_loader.dataset)
        val_loss_history.append(avg_val_loss)

        if epoch % 20 == 0 or epoch == epochs - 1:
            print(f"Epoch {epoch}/{epochs} | Train Loss: {avg_train_loss:.6f} | Val Loss: {avg_val_loss:.6f}")

        # Early stopping
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            torch.save(model.state_dict(), "models/autoencoder.pth")
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print("Early stopping triggered.")
                break

    model.load_state_dict(torch.load("models/autoencoder.pth"))
    return model, train_loss_history, val_loss_history


def export_to_onnx(model, X_scaled, path="models/autoencoder.onnx"):
    model.eval()
    example_input = torch.tensor(X_scaled[:1].astype('float32'))

    torch.onnx.export(
        model,
        example_input,
        path,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
        opset_version=11
    )
    print(f"✅ Modello esportato in ONNX: {path}")

