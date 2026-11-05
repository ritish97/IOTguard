@echo off
echo ========================================================
echo  Launching IoTGuard Interactive Web Dashboard
echo ========================================================
python -c "import sys; from streamlit.web import cli as stcli; sys.argv = ['streamlit', 'run', r'%~dp0dashboard\app.py']; stcli.main()"
pause
