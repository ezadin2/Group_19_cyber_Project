import streamlit as st
import auth_functions

st.header("Welcome to Data Privacy Compliance Checker Tool.")
st.write("Please log in or sign up to continue.")

# Not logged in
if 'user_info' not in st.session_state:
    col1, col2, col3 = st.columns([1, 4, 1])
    # central notification area under the tabs
    auth_notification = col2.empty()

    tab_login, tab_signup, tab_forgot = col2.tabs(["Log In", "Sign Up", "Forgot Password"])

    # Log In
    with tab_login:
        login_form = st.form(key='login_form', clear_on_submit=False)
        login_email = login_form.text_input(label='Email')
        login_password = login_form.text_input(label='Password', type='password')

        if login_form.form_submit_button(label='Log In', use_container_width=True, type='primary'):
            with auth_notification:
                with st.spinner('Signing in...'):
                    auth_functions.sign_in(login_email, login_password)

    # Sign Up
    with tab_signup:
        signup_form = st.form(key='signup_form', clear_on_submit=False)
        signup_email = signup_form.text_input(label='Email')
        signup_password = signup_form.text_input(label='Password', type='password')

        if signup_form.form_submit_button(label='Create Account', use_container_width=True, type='primary'):
            with auth_notification:
                with st.spinner('Creating account...'):
                    auth_functions.create_account(signup_email, signup_password)

    # Password Reset
    with tab_forgot:
        forgot_form = st.form(key='forgot_password_form', clear_on_submit=False)
        reset_email = forgot_form.text_input(label='Email')

        if forgot_form.form_submit_button(label='Send Password Reset Email', use_container_width=True, type='primary'):
            with auth_notification:
                with st.spinner('Sending password reset link...'):
                    auth_functions.reset_password(reset_email)

    # Authentication success and warning messages
    if 'auth_success' in st.session_state:
        auth_notification.success(st.session_state.auth_success)
        del st.session_state['auth_success']
    elif 'auth_warning' in st.session_state:
        auth_notification.warning(st.session_state.auth_warning)
        del st.session_state['auth_warning']

# Logged in
else:
    st.header('User information')
    st.write(st.session_state.user_info)

    st.header('Settings')
    col1, col2, *rest = st.columns(6)
    col1.button(label='Sign Out', on_click=auth_functions.sign_out, type='secondary')

    # Delete Account (confirm with password)
    st.subheader("Delete Account")
    delete_form = st.form(key='delete_account_form', clear_on_submit=False)
    confirm_password = delete_form.text_input(label='Confirm your password', type='password')
    if delete_form.form_submit_button(label='Delete Account', type='secondary'):
        st.rerun()
        auth_functions.delete_account(confirm_password)
