

import os
import threading
import time
from ipaddress import ip_address
import subprocess
import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from django.conf import settings

class IntrusionDetectionSystem:
    def __init__(self):
        # Load saved model and preprocessing tools
        self.model = None
        self.scaler = None
        self.label_encoder = None
        model_path = os.path.join(settings.BASE_DIR, 'ml_models', 'ids_dnn_model_7features.h5')
        scaler_path = os.path.join(settings.BASE_DIR, 'ml_models', 'scaler.pkl')
        encoder_path = os.path.join(settings.BASE_DIR, 'ml_models', 'label_encoder.pkl')
        
        # Verify file existence
        for path in [model_path, scaler_path, encoder_path]:
            if not os.path.exists(path):
                print(f"❌ Model file not found: {path}")
            else:
                print(f"✅ Model file found: {path}")
        
        try:
            self.model = load_model(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(encoder_path)
            print("✅ ML models loaded successfully")
        except Exception as e:
            print(f"❌ Error loading ML models: {e}")
            self.model = None
            self.scaler = None
            self.label_encoder = None
        
        # Track processed IPs and detection results
        self.processed_ips = set()
        self.blocked_ips = set()
        self.detection_log = []
        self.is_monitoring = False
        self.stop_requested = False
        self.monitoring_thread = None
        
        # Create reports directory
        self.reports_dir = os.path.join(settings.MEDIA_ROOT, 'intrusion_reports')
        os.makedirs(self.reports_dir, exist_ok=True)
        print(f"📂 Reports directory: {self.reports_dir}")
        self.latest_report_path = None

    def extract_features(self, packet):
        """Extract features from packet in the same format as training data"""
        if not IP in packet:
            print(f"⚠️ Packet skipped: No IP layer (Packet summary: {packet.summary()})")
            return None
        
        proto = 0  # default: other
        service = 0
        flag = 0
        
        if packet.haslayer(TCP):
            proto = 1
            service = packet[TCP].dport
            flag = int(packet[TCP].flags)
        elif packet.haslayer(UDP):
            proto = 2
            service = packet[UDP].dport
        
        ttl = packet[IP].ttl
        pkt_len = len(packet)
        src_bytes = len(packet[IP].payload)
        dst_bytes = len(packet[IP].payload)
        
        # Create DataFrame with feature names
        feature_names = ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'ttl', 'pkt_len']
        feature_vector = np.array([[proto, service, flag, src_bytes, dst_bytes, ttl, pkt_len]])
        features_df = pd.DataFrame(feature_vector, columns=feature_names)
        print(f"🔍 Features extracted: {feature_vector}")
        return features_df

    def block_ip(self, ip_addr):
        """Block IP using Windows firewall with unique rule name"""
        try:
            rule_name = f"BlockMaliciousIP_{ip_addr}_{int(time.time())}"
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_addr}"],
                check=True, capture_output=True, text=True
            )
            print(f"✅ Successfully blocked IP: {ip_addr} (Rule: {rule_name})")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to block {ip_addr}: {e} - Output: {e.output}")
            return False

    def predict_intrusion(self, packet):
        """Predict intrusion and log results"""
        if not self.model:
            print("❌ Model not loaded, cannot process packets")
            return
        
        if not IP in packet:
            print(f"⚠️ Packet skipped: No IP layer (Packet summary: {packet.summary()})")
            return
            
        src_ip = packet[IP].src
        print(f"📥 Processing packet from IP: {src_ip}")
        
        # Temporarily disable IP skipping for debugging
        # if src_ip in self.processed_ips:
        #     print(f"⏭️ IP {src_ip} already processed, skipping")
        #     return
        
        features = self.extract_features(packet)
        if features is not None:
            try:
                # Scale features
                features_scaled = self.scaler.transform(features)
                print(f"🔧 Scaled features: {features_scaled}")
                
                # Make prediction
                prediction = self.model.predict(features_scaled, verbose=0)
                max_prob = np.max(prediction)
                predicted_class_idx = np.argmax(prediction)
                predicted_class = self.label_encoder.inverse_transform([predicted_class_idx])[0]
                
                # Log detection result
                detection_result = {
                    'timestamp': datetime.now(),
                    'source_ip': src_ip,
                    'prediction': predicted_class,
                    'confidence': float(max_prob),
                    'action_taken': 'none',
                    'packet_size': len(packet),
                    'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'Other'
                }
                
                # Print detailed output
                print(f"\n{'='*60}")
                print(f"Timestamp: {detection_result['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Source IP: {src_ip}")
                print(f"Prediction: {predicted_class}")
                print(f"Confidence: {max_prob:.4f}")
                
                # Block if malicious with high confidence
                if predicted_class.lower() != 'normal' and max_prob >= 0.9:
                    if src_ip not in self.blocked_ips:
                        if self.block_ip(src_ip):
                            self.blocked_ips.add(src_ip)
                            detection_result['action_taken'] = 'blocked'
                            print(f"Action: ❌ BLOCKED IP {src_ip}")
                        else:
                            detection_result['action_taken'] = 'block_failed'
                            print(f"Action: ⚠️ FAILED TO BLOCK {src_ip}")
                    else:
                        detection_result['action_taken'] = 'already_blocked'
                        print(f"Action: ⏭️ Already blocked")
                else:
                    detection_result['action_taken'] = 'none'
                    print(f"Action: ✅ No action needed")
                
                print(f"{'='*60}")
                
                self.detection_log.append(detection_result)
                self.processed_ips.add(src_ip)
                
                # Clear processed IPs periodically
                if len(self.processed_ips) > 100:
                    self.processed_ips.clear()
                    print("🧹 Cleared processed IPs")
                    
            except Exception as e:
                print(f"❌ Prediction error for {src_ip}: {e}")

    def start_monitoring(self, duration_seconds=None, iface=None):
        """Start monitoring network traffic"""
        if self.is_monitoring:
            print("⚠️ Monitoring already in progress")
            return False
            
        self.is_monitoring = True
        self.stop_requested = False
        self.detection_log = []  # Clear previous logs
        
        print(f"🔍 Starting intrusion detection on interface {iface or 'default'}...")
        
        def monitor():
            try:
                # Use stop_filter to allow manual stopping
                def stop_filter(packet):
                    return self.stop_requested

                sniff(prn=self.predict_intrusion, stop_filter=stop_filter, store=0, timeout=duration_seconds, iface=iface)
                print("✅ Monitoring completed or stopped")
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
            finally:
                self.is_monitoring = False
                print(f"📋 Detection log contains {len(self.detection_log)} entries")
        
        self.monitoring_thread = threading.Thread(target=monitor)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        return True

    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.is_monitoring:
            self.stop_requested = True
            print("🛑 Stop requested for monitoring")
            return True
        return False

    def wait_for_monitoring_complete(self):
        """Wait for monitoring to complete"""
        if self.monitoring_thread:
            self.monitoring_thread.join()
            print("🛑 Monitoring thread completed")

    def generate_pdf_report(self, company_name="Admin", receiver_name="Network", file_name="Live Monitoring"):
        """Generate PDF report of intrusion detection results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"intrusion_report_{timestamp}.pdf"
        report_path = os.path.join(self.reports_dir, report_filename)
        
        try:
            doc = SimpleDocTemplate(report_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue,
                alignment=TA_CENTER
            )
            story.append(Paragraph("Intrusion Detection Report", title_style))
            story.append(Spacer(1, 20))
            
            info_data = [
                ['Report Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                # ['Sender Company:', company_name],
                # ['Receiver Company:', receiver_name],
                ['File Transmitted:', file_name],
                # ['Monitoring Duration:', f"{30} seconds"],
                ['Total Detections:', str(len(self.detection_log))],
                ['Threats Blocked:', str(len([d for d in self.detection_log if d['action_taken'] == 'blocked']))]
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 3*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(info_table)
            story.append(Spacer(1, 30))
            
            if self.detection_log:
                story.append(Paragraph("Detection Summary", styles['Heading2']))
                story.append(Spacer(1, 12))
                
                detection_data = [['Timestamp', 'Source IP', 'Threat Type', 'Confidence', 'Action', 'Protocol', 'Packet Size']]
                for detection in self.detection_log[-20:]:
                    detection_data.append([
                        detection['timestamp'].strftime("%H:%M:%S"),
                        detection['source_ip'],
                        detection['prediction'],
                        f"{detection['confidence']:.4f}",
                        detection['action_taken'].replace('_', ' ').title(),
                        detection['protocol'],
                        f"{detection['packet_size']} bytes"
                    ])
                
                detection_table = Table(detection_data, colWidths=[1*inch, 1.5*inch, 1.2*inch, 1*inch, 1*inch, 0.8*inch, 1*inch])
                detection_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(detection_table)
                story.append(Spacer(1, 30))
                
                story.append(Paragraph("Detailed Threat Logs", styles['Heading2']))
                story.append(Spacer(1, 12))
                
                detail_style = ParagraphStyle(
                    'DetailStyle',
                    parent=styles['Normal'],
                    fontSize=10,
                    spaceAfter=12,
                    alignment=TA_LEFT,
                    leading=14
                )
                
                for detection in self.detection_log:
                    action_emoji = "❌" if detection['action_taken'] == 'blocked' else "⚠️" if detection['action_taken'] == 'block_failed' else "🔄" if detection['action_taken'] == 'already_blocked' else "✅"
                    action_text = f"{action_emoji} <b>{detection['action_taken'].upper()} IP {detection['source_ip']}</b>" if detection['action_taken'] != 'none' else f"{action_emoji} <b>NO ACTION NEEDED</b>"
                    
                    detail_text = (
                        f"<b>Timestamp:</b> {detection['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                        f"<b>Source IP:</b> {detection['source_ip']}<br/>"
                        f"<b>Prediction:</b> {detection['prediction']}<br/>"
                        f"<b>Confidence:</b> {detection['confidence']:.4f}<br/>"
                        f"<b>Action:</b> <font color='red'>{action_text}</font><br/>"
                        f"<b>Protocol:</b> {detection['protocol']}<br/>"
                        f"<b>Packet Size:</b> {detection['packet_size']} bytes<br/>"
                        f"========="
                    )
                    story.append(Paragraph(detail_text, detail_style))
                    story.append(Spacer(1, 10))
            else:
                story.append(Paragraph("No intrusions detected during monitoring period.", styles['Normal']))
                story.append(Spacer(1, 20))
            
            story.append(Paragraph("Security Summary", styles['Heading2']))
            threats_detected = len([d for d in self.detection_log if d['prediction'].lower() != 'normal'])
            if threats_detected == 0:
                summary_text = "✅ <b>SECURE TRANSMISSION</b>: No security threats were detected during the file transfer."
            else:
                threats_blocked = len([d for d in self.detection_log if d['action_taken'] == 'blocked'])
                summary_text = (
                    f"⚠️ <b>THREATS DETECTED</b>: {threats_detected} potential threats identified. "
                    f"{threats_blocked} threats were successfully blocked."
                )
            
            story.append(Paragraph(summary_text, styles['Normal']))
            
            doc.build(story)
            print(f"📄 PDF report generated: {report_path}")
            self.latest_report_path = report_path
            return report_path
        except Exception as e:
            print(f"❌ Error generating PDF report: {e}")
            return None

# Global instance
ids_system = IntrusionDetectionSystem()

def run_intrusion_detection(company_name, receiver_name, file_name, iface=None):
    """
    Run intrusion detection and generate report
    """
    try:
        print(f"🚀 Starting intrusion detection for {company_name} -> {receiver_name}, file: {file_name}")
        if not ids_system.start_monitoring(duration_seconds=30, iface=iface):
            print("❌ Failed to start monitoring")
            return None
        
        ids_system.wait_for_monitoring_complete()
        
        report_path = ids_system.generate_pdf_report(company_name, receiver_name, file_name)
        if report_path:
            print(f"✅ Report generated successfully: {report_path}")
        else:
            print("❌ Report generation failed")
        
        return {
            'report_path': report_path,
            'threats_detected': len([d for d in ids_system.detection_log if d['prediction'].lower() != 'normal']),
            'threats_blocked': len([d for d in ids_system.detection_log if d['action_taken'] == 'blocked']),
            'total_packets': len(ids_system.detection_log)
        }
    except Exception as e:
        print(f"❌ Error during intrusion detection: {e}")
        return None