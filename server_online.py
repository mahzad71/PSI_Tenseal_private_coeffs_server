import socket
import tenseal as ts
import pickle
import numpy as np
from math import log2
import logging
import pdb
import json

from parameters import number_of_hashes, bin_capacity, alpha, ell, plain_modulus, poly_modulus_degree
from auxiliary_functions import power_reconstruct
from oprf import server_prf_online_parallel

oprf_server_key = 1234567891011121314151617181920
from time import time

log_no_hashes = int(log2(number_of_hashes)) + 1
base = 2 ** ell
minibin_capacity = int(bin_capacity / alpha)
logB_ell = int(log2(minibin_capacity) / ell) + 1 # <= 2 ** HE.depth

# Initialize and listen on the server socket
serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(('localhost', 4470))
    serv.listen(1)
    logging.info("Server is listening...")
except Exception as e:
    logging.error(f"Error setting up server socket: {e}")
    exit(1)

#------------------------------Step0: Setting the public and private contexts for the BFV Homorphic Encryption scheme-------------------------------
pdb.set_trace()
private_context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=poly_modulus_degree, plain_modulus=plain_modulus)
public_context = ts.context_from(private_context.serialize())
public_context.make_context_public()
    

g = open('server_preprocessed', 'rb')
poly_coeffs = pickle.load(g)

# For the online phase of the server, we need to use the columns of the preprocessed database
transposed_poly_coeffs = np.transpose(poly_coeffs).tolist()
print("Transposed coeffs before encryption:", transposed_poly_coeffs)
enc_transposed_poly_coeffs = []
for transposed_poly_coeff in transposed_poly_coeffs:
    enc_transposed_poly_coeff = ts.bfv_vector(private_context,transposed_poly_coeff)
    enc_transposed_poly_coeffs.append(enc_transposed_poly_coeff)

# Serializing encrypted coefficients for saving to file
serialized_enc_transposed_poly_coeffs = [coeff.serialize() for coeff in enc_transposed_poly_coeffs]

# Writing serialized encrypted coefficients to a file using pickle
with open('encrypted_transposed_coeffs.pkl', 'wb') as f:
    pickle.dump(serialized_enc_transposed_poly_coeffs, f)

print("Serialized and encrypted coefficients have been written to 'encrypted_transposed_coeffs.pkl'")


for i in range(1):
    conn, addr = serv.accept()

#---------------------------------------------------------Step1: Sending the public context to client------------------------------------------------
    pdb.set_trace()
    try:
        # Serializing public context to be sent to the client
        context_serialized = public_context.serialize()
        #pdb.set_trace()
        context_serialized_to_be_sent = pickle.dumps(context_serialized, protocol=None)
        t1 = time()
        logging.info("Serializing public context to be sent to the client.")

        # Preparing length information
        L = len(context_serialized_to_be_sent)
        sL = str(L) + ' ' * (10 - len(str(L))) #pad len to 10 bytes
        public_key_communication = L 

        # Sending the length of the message first
        conn.sendall(sL.encode())
        # Sending the serialized public context
        conn.sendall(context_serialized_to_be_sent)
        #pdb.set_trace()
        logging.info("Sending the public key context to the client....")
        t3 = time()

    except Exception as e:
        logging.error(f"Error sending public context to client: {e}")

#----------------------------------------------------Step2: OPRF online in server for client's data------------------------------------------------------
    pdb.set_trace()
    L = conn.recv(10).decode().strip()
    L = int(L, 10)
    # OPRF layer: the server receives the encoded set elements as curve points
    encoded_client_set_serialized = b""
    while len(encoded_client_set_serialized) < L:
        data = conn.recv(4096)
        if not data: break
        encoded_client_set_serialized += data   
    encoded_client_set = pickle.loads(encoded_client_set_serialized)
    t0 = time()
    # The server computes (parallel computation) the online part of the OPRF protocol, using its own secret key
    PRFed_encoded_client_set = server_prf_online_parallel(oprf_server_key, encoded_client_set)
    PRFed_encoded_client_set_serialized = pickle.dumps(PRFed_encoded_client_set, protocol=None)
    L = len(PRFed_encoded_client_set_serialized)
    sL = str(L) + ' ' * (10 - len(str(L))) #pad len to 10 bytes

    conn.sendall((sL).encode())
    conn.sendall(PRFed_encoded_client_set_serialized)    
    print(' * OPRF layer done!')
    t1 = time()

    #-------------------------------------------------------Step3: Getting encrypted data from client and recover the context---------------------------------------------------------
    pdb.set_trace()
    L = conn.recv(10).decode().strip()
    L = int(L, 10)

    # The server receives bytes that represent the public HE context and the query ciphertext
    final_data = b""
    while len(final_data) < L:
        data = conn.recv(4096)
        if not data: break
        final_data += data

    t2 = time()    
    # Here we recover the context and ciphertext received from the received bytes
    received_data = pickle.loads(final_data)
    srv_context = ts.context_from(received_data[0])
    received_enc_query_serialized = received_data[1]
    enc_client_data = [[None for j in range(logB_ell)] for i in range(base - 1)]
    #received_enc_query = [[None for j in range(logB_ell)] for i in range(base - 1)]
    for i in range(base - 1):
        for j in range(logB_ell):
            if ((i + 1) * base ** j - 1 < minibin_capacity):
                 enc_client_data[i][j] = ts.bfv_vector_from(private_context, received_enc_query_serialized[i][j])#.decrypt()
                 print(f"Type of enc_client_data[{i}][{j}]: {type(enc_client_data[i][j])}, Value: {enc_client_data[i][j]}")
    #!!!!!print(f"Type of decrypted value: {type(decrypted_value)}, Value: {decrypted_value}")  # Debug
    #print("Decrypted Client's data in server:", received_enc_query)
    # Write the decrypted data to a file
    with open('encrypted__cllient_data.txt', 'w') as file:
        for row in enc_client_data:
            line = ', '.join(str(x) for x in row)  # This will convert each item in the row to a string, skipping 'None' values
            file.write(line + '\n')
    #!!!!!!!!print(f"Type of decrypted item: {type(decrypted_value)}")
    #!!!!!!print(f"Type of decrypted_value[{i}][{j}]: {type(decrypted_value[i][j])}, Value: {decrypted_value[i][j]}")

   #-----------------------------------------------------Step4: Recover encrypted powers encrypted powers-------------------------------------------------------------------
    pdb.set_trace()
    # Here we recover all the encrypted powers Enc(y), Enc(y^2), Enc(y^3) ..., Enc(y^{minibin_capacity}), from the encrypted windowing of y.
    # These are needed to compute the polynomial of degree minibin_capacit
    all_powers = [None for i in range(minibin_capacity)]
    for i in range(base - 1):
        for j in range(logB_ell):
            if ((i + 1) * base ** j - 1 < minibin_capacity):
                all_powers[(i + 1) * base ** j - 1] = enc_client_data[i][j]
    #"""""for p_value in decrypted_value:
    for k in range(minibin_capacity):
        if all_powers[k] == None:
            all_powers[k] = power_reconstruct(enc_client_data, k + 1)
    all_powers = all_powers[::-1]
    print("All powers results:", all_powers)    
    # Decrypt each element in all_powers
    #decrypted_all_powers = [power.decrypt() if power is not None else None for power in all_powers]

    #2222serialized_all_powers = []
    #22222for power in all_powers:
        # Serialize using TenSEAL's serialize method
        #2222serialized_power = power.serialize()
        #2222serialized_all_powers.append(serialized_power)

    #2222all_powers_decryption = []
    #for k in range(minibin_capacity):
    #2222for power in serialized_all_powers:
        #2222all_powers_decryption = ts.bfv_vector_from(private_context, power).decrypt()
    #2222print("Decrypted all powers results:", all_powers_decryption) 

    #serialized_data = [vector.serialize() for vector in all_powers_decryption]
    #with open('Decrypted_all_powers.txt', 'w') as file:
        #for item in serialized_data:
            #f.write(str(item) + '\n')
#----------------------------------------------------------Step5: Dot product between Coeffs and server's data---------------------------------------------------

    # Server sends alpha ciphertexts, obtained from performing dot_product between the polynomial coefficients from the preprocessed server database and all the powers Enc(y), ..., Enc(y^{minibin_capacity})
    pdb.set_trace()
    srv_answer = []
    srv_answer_serialized = []
    #for p_value in decrypted_value:
    for i in range(alpha):
        # the rows with index multiple of (B/alpha+1) have only 1's
        dot_product = all_powers[0]
        for j in range(1, minibin_capacity):
            dot_product = dot_product + enc_transposed_poly_coeffs[(minibin_capacity + 1) * i + j] * all_powers[j]
        dot_product = dot_product + enc_transposed_poly_coeffs[(minibin_capacity + 1) * i + minibin_capacity]
        print("Dot product is:", dot_product)
        srv_answer.append(dot_product)
    for product_value in srv_answer:
        srv_answer_serialized.append(product_value.serialize())
        # Here is the vector of decryptions of the answer
        
        #ciphertexts = pickle.loads(srv_answer)
    decryptions = []
    for ct in srv_answer_serialized:
        decryptions.append(ts.bfv_vector_from(private_context, ct).decrypt())
    print("Decrypted intersection dot prodoct is:", decryptions)
    # Write the decrypted data to a file
    with open('Decrypted_intersection_dotprodoct.txt', 'w') as file:
        for row in decryptions:
            line = ', '.join(str(x) for x in row)  # This will convert each item in the row to a string, skipping 'None' values
            file.write(line + '\n')

    

#--------------------------------------------------------Step6: Sending answers to the client----------------------------------------------------------------------

    # The answer to be sent to the client is prepared
    pdb.set_trace()
    response_to_be_sent = pickle.dumps(decryptions, protocol=None)
    t3 = time()
    L = len(response_to_be_sent)
    sL = str(L) + ' ' * (10 - len(str(L))) #pad len to 10 bytes

    conn.sendall((sL).encode())
    conn.sendall(response_to_be_sent)

    # Close the connection
    print("Client disconnected \n")
    print('Server ONLINE computation time {:.2f}s'.format(t1 - t0 + t3 - t2))

    conn.close()
