package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import io.grpc.*;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.util.*;

public class ServerCryptographicInterceptor implements ServerInterceptor {
  Map<String, List<String>> queue = new HashMap<>();
  public boolean isNotQueued(String methodName) {
    return queue.get(methodName).isEmpty();
  }
  public String getFromQueue(String methodName) {
    return queue.get(methodName).get(0);
  }

  public String getClientHash(String methodName) {
    if (isNotQueued(methodName))
      throw new RuntimeException();
    return getFromQueue(methodName);
  }

  @Override
  public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
    ServerCall<ReqT, RespT> call,
    final Metadata headers,
    ServerCallHandler<ReqT, RespT> next
  ) {
    // For now nothing to do here
    ServerCall<ReqT, RespT> wrapperCall =
      new ForwardingServerCall.SimpleForwardingServerCall<>(call) {
        @Override
        public void request(int numMessages) {
            call.request(numMessages);
        }
        @Override
        public void sendHeaders(Metadata headers) {
            call.sendHeaders(headers);
        }
        @Override
        public void sendMessage(RespT message) {
            call.sendMessage(message);
        }
        @Override
        public void close(Status status, Metadata trailers) {
              call.close(status, trailers);
          }
    };
    ServerCall.Listener<ReqT> listener = next.startCall(wrapperCall, headers);

    String addressHash = Utils.byteToHex(Objects.requireNonNull(
            call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR)).toString().getBytes()
    );
    String fullMethodName = call.getMethodDescriptor().getFullMethodName();
    if (queue.get(fullMethodName) == null) {
      ArrayList<String> list = new ArrayList<>();
      list.add(addressHash);
      queue.put(fullMethodName, list);
    } else queue.get(fullMethodName).add(addressHash);
    return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(listener) {
      private boolean cached = false;
      private void clearClientCache() {
        if (cached) queue.get(fullMethodName).remove(0);
        cached = false;
      }
      @Override
      public void onMessage(ReqT message) {
        listener.onMessage(message);
      }
      @Override
      public void onCancel() {
        clearClientCache();
        super.onCancel();
      }
      @Override
      public void onComplete() {
        clearClientCache();
        super.onComplete();
      }
    };
  }
}