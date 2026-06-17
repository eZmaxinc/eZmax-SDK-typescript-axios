# CustomEzmaxpartnerproductSubscribe

Request for POST /1/webhookdocumentation/subscribe

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pksEzmaxcustomerCode** | **string** | The Ezmaxcustomer code | [optional] [default to undefined]
**sInfrastructureenvironmenttypeDescription** | **string** | The environment type Description | [optional] [default to undefined]
**sCompanyName1** | **string** | The Name of the Company in French | [optional] [default to undefined]
**sCompanyName2** | **string** | The Name of the Company in English | [optional] [default to undefined]
**fkiSystemconfigurationtypeID** | **number** | The unique ID of the Systemconfigurationtype | [optional] [default to undefined]
**sSystemconfigurationtypeDescription1** | **string** | The description of the Systemconfigurationtype in the language of the requester | [optional] [default to undefined]
**sSystemconfigurationtypeDescription2** | **string** | The description of the Systemconfigurationtype in the language of the requester | [optional] [default to undefined]
**fkiEzmaxpartnerID** | **number** | The unique ID of the Ezmaxpartner | [optional] [default to undefined]
**sEzmaxpartnerName1** | **string** | The name of the Ezmaxpartner in french | [optional] [default to undefined]
**sEzmaxpartnerName2** | **string** | The name of the Ezmaxpartner in english | [optional] [default to undefined]
**fkiEzmaxpartnerproductID** | **number** | The unique ID of the Ezmaxpartnerproduct | [optional] [default to undefined]
**sEzmaxpartnerproductName1** | **string** | The name1 of the Ezmaxpartnerproduct | [optional] [default to undefined]
**sEzmaxpartnerproductName2** | **string** | The name2 of the Ezmaxpartnerproduct | [optional] [default to undefined]
**fkiEzmaxpartnerproductstageID** | **number** | The unique ID of the Ezmaxpartnerproductstage | [optional] [default to undefined]
**sEzmaxpartnerproductstageCode** | **string** | The code of the sEzmaxpartnerproductstage | [optional] [default to undefined]
**sUserLoginName** | **string** | The login name of the User. | [optional] [default to undefined]
**sUserFirstName** | **string** | The first name of the user | [optional] [default to undefined]
**sUserLastName** | **string** | The last name of the user | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [optional] [default to undefined]
**objAddress** | [**AddressRequestCompound**](AddressRequestCompound.md) |  | [optional] [default to undefined]
**objphone** | [**PhoneRequestCompoundV2**](PhoneRequestCompoundV2.md) |  | [optional] [default to undefined]
**objEmail** | [**EmailRequestCompound**](EmailRequestCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CustomEzmaxpartnerproductSubscribe } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzmaxpartnerproductSubscribe = {
    pksEzmaxcustomerCode,
    sInfrastructureenvironmenttypeDescription,
    sCompanyName1,
    sCompanyName2,
    fkiSystemconfigurationtypeID,
    sSystemconfigurationtypeDescription1,
    sSystemconfigurationtypeDescription2,
    fkiEzmaxpartnerID,
    sEzmaxpartnerName1,
    sEzmaxpartnerName2,
    fkiEzmaxpartnerproductID,
    sEzmaxpartnerproductName1,
    sEzmaxpartnerproductName2,
    fkiEzmaxpartnerproductstageID,
    sEzmaxpartnerproductstageCode,
    sUserLoginName,
    sUserFirstName,
    sUserLastName,
    fkiUserID,
    fkiLanguageID,
    objAddress,
    objphone,
    objEmail,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
