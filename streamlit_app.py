import streamlit as st
import pandas as pd
import ipaddress

# --- Function to load firewall rules from Excel ---
def load_firewall_rules(file):
    df = pd.read_excel(file)
    return df

# --- Function to check if a rule matches customer subnets ---
def match_rules(firewall_rules, customer_subnets):
    matched_rules = []
    
    for _, rule in firewall_rules.iterrows():
        try:
            src_net = ipaddress.ip_network(rule['Source'], strict=False)
            dst_net = ipaddress.ip_network(rule['Destination'], strict=False)
        except ValueError:
            continue  # Skip invalid entries

        for subnet in customer_subnets:
            try:
                customer_net = ipaddress.ip_network(subnet.strip(), strict=False)
                if customer_net.overlaps(src_net) or customer_net.overlaps(dst_net):
                    matched_rules.append(rule)
                    break
            except ValueError:
                continue

    return pd.DataFrame(matched_rules)

# --- Streamlit UI ---
st.title("Customer Firewall Rule Extractor")

st.markdown("""
This tool helps extract firewall rules relevant to a specific customer based on their IP subnets.
Upload an Excel file with firewall rules and input the customer subnets below.
""")

# Upload Excel file
uploaded_file = st.file_uploader("Upload Firewall Rules Excel File", type=["xlsx"])

# Input customer subnets
subnet_input = st.text_area("Enter Customer Subnets (one per line)", height=150)

if uploaded_file and subnet_input:
    st.subheader("Matching Rules")
    firewall_rules_df = load_firewall_rules(uploaded_file)
    customer_subnets = subnet_input.strip().splitlines()
    matched_df = match_rules(firewall_rules_df, customer_subnets)

    st.write(f"Found {len(matched_df)} matching rules.")
    st.dataframe(matched_df)

    # Option to download result
    csv = matched_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Matching Rules as CSV",
        data=csv,
        file_name='customer_matched_rules.csv',
        mime='text/csv'
    )
else:
    st.info("Please upload a firewall rules file and enter customer subnets to begin.")
