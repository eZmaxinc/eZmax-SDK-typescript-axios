# EzmaxinvoicingsummaryinternalResponse

A Ezmaxinvoicingsummaryinternal Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingsummaryinternalID** | **number** | The unique ID of the Ezmaxinvoicingsummaryinternal | [optional] [default to undefined]
**objEzmaxinvoicingsummaryinternalDescription** | [**MultilingualEzmaxinvoicingsummaryinternalDescription**](MultilingualEzmaxinvoicingsummaryinternalDescription.md) |  | [default to undefined]
**sEzmaxinvoicingsummaryinternalDescriptionX** | **string** | The Ezmaxinvoicingsummaryinternal description in the language of the requester | [default to undefined]
**fkiEzmaxinvoicingID** | **number** | The unique ID of the Ezmaxinvoicing | [optional] [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [default to undefined]
**sBillingentityinternalDescriptionX** | **string** | The description of the Billingentityinternal in the language of the requester | [default to undefined]

## Example

```typescript
import { EzmaxinvoicingsummaryinternalResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingsummaryinternalResponse = {
    pkiEzmaxinvoicingsummaryinternalID,
    objEzmaxinvoicingsummaryinternalDescription,
    sEzmaxinvoicingsummaryinternalDescriptionX,
    fkiEzmaxinvoicingID,
    fkiBillingentityinternalID,
    sBillingentityinternalDescriptionX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
