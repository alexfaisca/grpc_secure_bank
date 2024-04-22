package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import io.grpc.*;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.util.*;

public class ServerCryptographicInterceptor implements ServerInterceptor {
  private static final class ClassWizard<T> {
    private final Class<T> type;
    public ClassWizard(Class<T> m) {
      this.type = m;
    }
    public Class<T> get() {
      return this.type;
    }
  }
  Map<Class, List<String>> queue = new HashMap<>();

  private boolean isNotQueued(Class requestClass) {
      return queue.get(requestClass).isEmpty();
  }

  public String getFromQueue(Class requestClass) {
      return queue.get(requestClass).get(0);
  }

  public <ReqT> String getClientHash(ReqT request) {
    if (isNotQueued(request.getClass()))
      throw new RuntimeException();
    return getFromQueue(request.getClass());
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
    return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(listener) {
      private Class clazz;
      private boolean cached = false;
      private void cacheClient(ReqT m) {
        clazz = new ClassWizard<>(m.getClass()).get();
        System.out.println(call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR));
        String addressHash = Utils.byteToHex(Objects.requireNonNull(
          call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR)).toString().getBytes()
        );
        if (queue.get(clazz) == null) {
          ArrayList<String> list = new ArrayList<>();
          list.add(addressHash);
          queue.put(clazz, list);
        } else queue.get(clazz).add(addressHash);
        cached = true;
      }
      private void clearCache() {
        if (cached) queue.get(clazz).remove(0);
        cached = false;
      }
      @Override
      public void onMessage(ReqT message) {
        cacheClient(message);
        listener.onMessage(message);
      }
      @Override
      public void onCancel() {
        clearCache();
        super.onCancel();
      }
      @Override
      public void onComplete() {
        clearCache();
        super.onComplete();
      }
    };
  }
}