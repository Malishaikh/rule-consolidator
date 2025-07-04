import streamlit as st
import pandas as pd
import ipaddress

# --- Function to load firewall rules and address groups from Excel ---
def load_firewall_and_addresses(file):
    xl = pd.ExcelFile(file)
    fw_df = xl.parse("Firewall Policy")
    ag_df = xl.parse("Address Group")
    return fw_df, ag_df

# --- Expand address groups into actual subnets (support multiple groups per field) ---
def resolve_address_group_field(field_value, address_group_df):
    all_addresses = []
    group_names = [name.strip() for name in str(field_value).split(',') if name.strip()]
    
    for name in group_names:
        matched = address_group_df[address_group_df['Group Name'] == name]
        if matched.empty:
            all_addresses.append(name)  # Treat as literal IP or subnet
        else:
            members = matched.iloc[0]['Members']
            member_list = [m.strip() for m in str(members).split(',') if m.strip()]
            all_addresses.extend(member_list)

    return all_addresses

# --- Function to check if a rule matches customer subnets ---
def match_rules(firewall_rules, address_groups, customer_subnets):
    matched_rules = []

    for _, rule in firewall_rules.iterrows():
        src_addrs = resolve_address_group_field(rule['Source'], address_groups)
        dst_addrs = resolve_address_group_field(rule['Destination'], address_groups)

        try:
            src_nets = [ipaddress.ip_network(addr, strict=False) for addr in src_addrs]
            dst_nets = [ipaddress.ip_network(addr, strict=False) for addr in dst_addrs]
        except ValueError:
            continue  # Skip invalid entries

        for subnet in customer_subnets:
            try:
                customer_net = ipaddress.ip_network(subnet.strip(), strict=False)
                if any(customer_net.overlaps(n) for n in src_nets + dst_nets):
                    matched_rules.append(rule)
                    break
            except ValueError:
                continue

    return pd.DataFrame(matched_rules)

# --- Streamlit UI ---
st.title("Customer Firewall Rule Extractor")

st.markdown("""
This tool extracts firewall rules relevant to a specific customer based on their IP subnets.
Upload an Excel file with 'Firewall Policy' and 'Address Group' tabs.
""")

# Upload Excel file
uploaded_file = st.file_uploader("Upload Firewall Rules Excel File", type=["xlsx"])

# Input customer subnets
subnet_input = st.text_area("Enter Customer Subnets (one per line)", height=150)

if uploaded_file and subnet_input:
    st.subheader("Matching Rules")
    firewall_rules_df, address_groups_df = load_firewall_and_addresses(uploaded_file)
    customer_subnets = subnet_input.strip().splitlines()
    matched_df = match_rules(firewall_rules_df, address_groups_df, customer_subnets)

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
