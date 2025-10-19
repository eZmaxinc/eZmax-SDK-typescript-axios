# EzmaxinvoicinguserResponseCompound

A Ezmaxinvoicinguser Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicinguserID** | **number** | The unique ID of the Ezmaxinvoicinguser | [optional] [default to undefined]
**fkiEzmaxinvoicingID** | **number** | The unique ID of the Ezmaxinvoicing | [optional] [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [default to undefined]
**sBillingentityinternalDescriptionX** | **string** | The description of the Billingentityinternal in the language of the requester | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**iEzmaxinvoicinguserEzsigndocument** | **number** | The number of ezsign documents | [default to undefined]
**bEzmaxinvoicinguserEzsignaccount** | **boolean** | Whether there is an eZsign account | [default to undefined]
**bEzmaxinvoicinguserBillableezsign** | **boolean** | Whether it is billable for eZsign | [default to undefined]
**eEzmaxinvoicinguserVariationezsign** | [**FieldEEzmaxinvoicinguserVariationezsign**](FieldEEzmaxinvoicinguserVariationezsign.md) |  | [default to undefined]
**objContactName** | [**CustomContactNameResponse**](CustomContactNameResponse.md) |  | [default to undefined]

## Example

```typescript
import { EzmaxinvoicinguserResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicinguserResponseCompound = {
    pkiEzmaxinvoicinguserID,
    fkiEzmaxinvoicingID,
    fkiBillingentityinternalID,
    sBillingentityinternalDescriptionX,
    fkiUserID,
    iEzmaxinvoicinguserEzsigndocument,
    bEzmaxinvoicinguserEzsignaccount,
    bEzmaxinvoicinguserBillableezsign,
    eEzmaxinvoicinguserVariationezsign,
    objContactName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
