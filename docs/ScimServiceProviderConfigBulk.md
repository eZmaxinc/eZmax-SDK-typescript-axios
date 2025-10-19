# ScimServiceProviderConfigBulk

A complex type that specifies bulk configuration options.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**supported** | **boolean** | A Boolean value specifying whether or not the operation is supported. | [default to undefined]
**maxOperations** | **number** | An integer value specifying the maximum number of operations. | [default to undefined]
**maxPayloadSize** | **number** | An integer value specifying the maximum payload size in bytes. | [default to undefined]

## Example

```typescript
import { ScimServiceProviderConfigBulk } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ScimServiceProviderConfigBulk = {
    supported,
    maxOperations,
    maxPayloadSize,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
