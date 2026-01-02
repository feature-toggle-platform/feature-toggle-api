package com.github.saqie.api.auth;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import pl.feature.toggle.service.model.security.correlation.CorrelationId;
import reactor.core.publisher.Mono;

import static pl.feature.toggle.service.model.security.correlation.CorrelationId.headerName;

@Component
final class CorrelationIdGlobalFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var correlationId = resolveCorrelationId(exchange.getRequest().getHeaders());

        ServerWebExchange mutated = exchange.mutate()
                .request(req -> req.headers(headers -> {
                    headers.remove(headerName());
                    headers.add(headerName(), correlationId.value());
                }))
                .build();

        mutated.getResponse().getHeaders().set(headerName(), correlationId.value());

        return chain.filter(mutated);
    }

    private CorrelationId resolveCorrelationId(HttpHeaders headers) {
        String existing = headers.getFirst(headerName());
        if (existing != null && !existing.isBlank()) {
            return CorrelationId.of(existing.trim());
        }
        return CorrelationId.generate();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}