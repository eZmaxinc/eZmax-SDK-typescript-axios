# ActivesessionGenerateFederationTokenV1ResponseMPayload

Payload for POST /1/object/activesession/generateFederationToken

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objApikeyfederation** | [**CustomApikeyfederation**](CustomApikeyfederation.md) |  | [default to undefined]
**sEzmaxcustomercodeUrl** | **string** | The url of the server the Ezmaxcustomer is located | [default to undefined]

## Example

```typescript
import { ActivesessionGenerateFederationTokenV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ActivesessionGenerateFederationTokenV1ResponseMPayload = {
    objApikeyfederation,
    sEzmaxcustomercodeUrl,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
