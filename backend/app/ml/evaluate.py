"""
Reloads the saved model and prints its evaluation metrics.
Run from backend/ with venv active:
    python -m app.ml.evaluate
"""
import os
import json

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def main():
    metrics_path = os.path.join(MODELS_DIR, "metrics.json")
    if not os.path.exists(metrics_path):
        print("No trained model found. Run `python -m app.ml.train` first.")
        return

    with open(metrics_path) as f:
        metrics = json.load(f)

    print("=== Saved Model Evaluation ===")
    print(f"Algorithm:  {metrics['algorithm']}")
    print(f"Classes:    {metrics['classes']}")
    print(f"Train rows: {metrics['train_rows']}  Test rows: {metrics['test_rows']}")
    print(f"Accuracy:   {metrics['accuracy']:.4f}")
    print(f"Precision:  {metrics['precision']:.4f}")
    print(f"Recall:     {metrics['recall']:.4f}")
    print(f"F1 Score:   {metrics['f1_score']:.4f}")


if __name__ == "__main__":
    main()