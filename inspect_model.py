import joblib
import xgboost as xgb

def main():
    model_path = 'xgboost_multiclass_realistic.pkl'
    try:
        model = joblib.load(model_path)
        print("Model loaded successfully.")
        
        if hasattr(model, 'feature_names_in_'):
            print("Features expected by the model:")
            print(list(model.feature_names_in_))
        else:
            print("Model does not have 'feature_names_in_' attribute.")
    except Exception as e:
        print(f"Error loading model: {e}")

if __name__ == "__main__":
    main()
