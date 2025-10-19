# CustomEzmaxpricingResponse

A Custom Ezmaxpricing Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxpricingID** | **number** | The unique ID of the Ezmaxpricing | [default to undefined]
**dEzmaxpricingRebateezsignallagents** | **string** | The rebate offered when eZsign is taken for all agents | [default to undefined]
**dtEzmaxpricingStart** | **string** | The start date of the Ezmaxpricing | [default to undefined]
**dtEzmaxpricingEnd** | **string** | The end date of the Ezmaxpricing | [optional] [default to undefined]

## Example

```typescript
import { CustomEzmaxpricingResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzmaxpricingResponse = {
    pkiEzmaxpricingID,
    dEzmaxpricingRebateezsignallagents,
    dtEzmaxpricingStart,
    dtEzmaxpricingEnd,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
