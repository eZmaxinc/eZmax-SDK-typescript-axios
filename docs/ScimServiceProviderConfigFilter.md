# ScimServiceProviderConfigFilter

A complex type that specifies FILTER options.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**supported** | **boolean** | A Boolean value specifying whether or not the operation is supported. | [default to undefined]
**maxResults** | **number** | An integer value specifying the maximum number of resources returned in a response. | [default to undefined]

## Example

```typescript
import { ScimServiceProviderConfigFilter } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ScimServiceProviderConfigFilter = {
    supported,
    maxResults,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
