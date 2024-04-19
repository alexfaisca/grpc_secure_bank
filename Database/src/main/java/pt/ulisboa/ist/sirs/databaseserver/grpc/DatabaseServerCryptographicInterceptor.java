package pt.ulisboa.ist.sirs.databaseserver.grpc;

import io.grpc.*;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.util.*;
import java.util.logging.Logger;

public class DatabaseServerCryptographicInterceptor implements ServerInterceptor {
    List<String> pendingAttributes = new ArrayList<>();
    Map<Class, List<String>> queue = new HashMap<>();
    private static final Logger logger = Logger.getLogger(DatabaseServerCryptographicInterceptor.class.getName());

    public boolean isQueued(Class requestClass) {
        return !queue.get(requestClass).isEmpty();
    }

    public String popFromQueue(Class requestClass) {
        return queue.get(requestClass).remove(0);
    }

    public String getFromQueue(Class requestClass) {
        return queue.get(requestClass).get(0);
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call,
            final Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        pendingAttributes.add(Utils.byteToHex(Objects.requireNonNull(call.getAttributes().get(Grpc.TRANSPORT_ATTR_LOCAL_ADDR)).toString().getBytes()));
        logger.info("header received from client:" + headers);
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
            @Override
            public void onMessage(ReqT message) {
                if (queue.get(message.getClass()) == null) {
                    ArrayList<String> list = new ArrayList<>();
                    list.add(pendingAttributes.remove(0));
                    queue.put(message.getClass(), list);
                } else queue.get(message.getClass()).add(pendingAttributes.remove(0));
                listener.onMessage(message);
            }
        };
    }
}