from django.shortcuts import render, redirect
from django.http import JsonResponse, FileResponse, Http404
from .finalpredictioncode import ids_system
import os
from datetime import datetime

def home(request):
    """Render the simplified home page"""
    return render(request, 'home.html')

def start_rds(request):
    """Start the Remote Detection System"""
    print("🚀 Start RDS request received")
    try:
        if ids_system.start_monitoring():
            print("✅ RDS monitoring initiated successfully")
            return JsonResponse({'status': 'success', 'message': 'RDS monitoring started'})
        else:
            print("⚠️ RDS start failed: already running")
            return JsonResponse({'status': 'error', 'message': 'RDS is already running'})
    except Exception as e:
        print(f"❌ RDS start explosion: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)})

def stop_rds(request):
    """Stop the Remote Detection System and return summary"""
    if ids_system.stop_monitoring():
        # Wait a moment for the sniff loop to terminate and thread to finish
        ids_system.wait_for_monitoring_complete()
        
        # Generate report
        report_path = ids_system.generate_pdf_report()
        
        # Gather stats
        total_packets = len(ids_system.detection_log)
        threats_detected = len([d for d in ids_system.detection_log if d['prediction'].lower() != 'normal'])
        threats_blocked = len([d for d in ids_system.detection_log if d['action_taken'] == 'blocked'])
        
        # Get latest 5 detections for the popup
        recent_detections = []
        for d in ids_system.detection_log[-5:]:
            recent_detections.append({
                'ip': d['source_ip'],
                'type': d['prediction'],
                'confidence': f"{d['confidence']*100:.1f}%",
                'action': d['action_taken'].replace('_', ' ').title()
            })

        return JsonResponse({
            'status': 'success',
            'stats': {
                'total_packets': total_packets,
                'threats_detected': threats_detected,
                'threats_blocked': threats_blocked
            },
            'recent': recent_detections,
            'report_generated': report_path is not None
        })
    else:
        return JsonResponse({'status': 'error', 'message': 'RDS is not running'})

def download_security_report(request):
    """Download the latest generated intrusion detection report"""
    try:
        report_path = ids_system.latest_report_path
        
        if not report_path or not os.path.exists(report_path):
            raise Http404("No recent security report found. Please run RDS first.")
        
        response = FileResponse(
            open(report_path, 'rb'),
            content_type='application/pdf'
        )
        
        filename = os.path.basename(report_path)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        raise Http404(f"Error downloading report: {e}")
