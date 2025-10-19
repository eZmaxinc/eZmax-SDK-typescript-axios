# GlobalEzmaxcustomerGetConfigurationV1Response

Response for GET /1/ezmaxcustomer/{pksEzmaxcustomerCode}/getConfiguration

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sInfrastructureregionCode** | **string** | The region code | [default to undefined]
**sInfrastructureregionCodeWeb** | **string** | The region code | [default to undefined]
**sInfrastructureenvironmenttypeDescription** | **string** | The environment type Description | [default to undefined]
**sCognitoClientIDExternal** | **string** | The ID of the client in Cognito | [optional] [default to undefined]
**sCognitoClientIDEzmaxpublic** | **string** | The ID of the client in Cognito | [default to undefined]

## Example

```typescript
import { GlobalEzmaxcustomerGetConfigurationV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: GlobalEzmaxcustomerGetConfigurationV1Response = {
    sInfrastructureregionCode,
    sInfrastructureregionCodeWeb,
    sInfrastructureenvironmenttypeDescription,
    sCognitoClientIDExternal,
    sCognitoClientIDEzmaxpublic,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
