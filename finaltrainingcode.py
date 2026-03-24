import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
import joblib

# All column names from NSL-KDD
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]


df = pd.read_csv('KDDTrain+.csv', names=columns)

df = df.drop(['difficulty_level'], axis=1)

features = ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes']
df = df[features + ['label']]


df['ttl'] = 0 #np.random.randint(30, 130, df.shape[0])  # simulate TTL
df['pkt_len'] = df['src_bytes'] + df['dst_bytes'] + 40  # estimate total packet length

for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])

label_encoder = LabelEncoder()
df['label'] = label_encoder.fit_transform(df['label'])

joblib.dump(label_encoder, 'label_encoder.pkl')

X = df[['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'ttl', 'pkt_len']]
y = df['label']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, 'scaler.pkl')

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

model = Sequential([
    Dense(64, activation='relu', input_dim=7),
    Dense(32, activation='relu'),
    Dense(len(np.unique(y)), activation='softmax')
])

model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test))

# Save model
model.save('ids_dnn_model_7features.h5')

print("✅ Model trained and saved using 7 features.")
