# ObjectInscriptionchecklistApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**inscriptionchecklistGetAutocompleteV2**](#inscriptionchecklistgetautocompletev2) | **GET** /2/object/inscriptionchecklist/getAutocomplete/{sSelector} | Retrieve Inscriptionchecklists and IDs|
|[**inscriptionchecklistGetAutocompleteV3**](#inscriptionchecklistgetautocompletev3) | **GET** /3/object/inscriptionchecklist/getAutocomplete/{sSelector} | Retrieve Inscriptionchecklists and IDs|

# **inscriptionchecklistGetAutocompleteV2**
> InscriptionchecklistGetAutocompleteV2Response inscriptionchecklistGetAutocompleteV2()

Get the list of Inscriptionchecklist to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectInscriptionchecklistApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionchecklistApi(configuration);

let sSelector: 'All'; //The type of Inscriptionchecklist to return (default to undefined)
let fkiID: string; //Specify which fkiID we want to display. (optional) (default to undefined)
let eType: 'Buyercontract' | 'Inscription' | 'Inscriptionnotauthenticated' | 'Inscriptiontemp' | 'Agent' | 'Broker' | 'Otherincome' | 'Rejectedoffertopurchase'; //The type of Inscriptionchecklist (optional) (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.inscriptionchecklistGetAutocompleteV2(
    sSelector,
    fkiID,
    eType,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Inscriptionchecklist to return | defaults to undefined|
| **fkiID** | [**string**] | Specify which fkiID we want to display. | (optional) defaults to undefined|
| **eType** | [**&#39;Buyercontract&#39; | &#39;Inscription&#39; | &#39;Inscriptionnotauthenticated&#39; | &#39;Inscriptiontemp&#39; | &#39;Agent&#39; | &#39;Broker&#39; | &#39;Otherincome&#39; | &#39;Rejectedoffertopurchase&#39;**]**Array<&#39;Buyercontract&#39; &#124; &#39;Inscription&#39; &#124; &#39;Inscriptionnotauthenticated&#39; &#124; &#39;Inscriptiontemp&#39; &#124; &#39;Agent&#39; &#124; &#39;Broker&#39; &#124; &#39;Otherincome&#39; &#124; &#39;Rejectedoffertopurchase&#39;>** | The type of Inscriptionchecklist | (optional) defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**InscriptionchecklistGetAutocompleteV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **inscriptionchecklistGetAutocompleteV3**
> InscriptionchecklistGetAutocompleteV3Response inscriptionchecklistGetAutocompleteV3()

Get the list of Inscriptionchecklist to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectInscriptionchecklistApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionchecklistApi(configuration);

let sSelector: 'All'; //The type of Inscriptionchecklist to return (default to undefined)
let fkiBuyercontractID: string; //Specify which Buyercontract we want to display. (optional) (default to undefined)
let fkiInscriptionID: string; //Specify which Inscription we want to display. (optional) (default to undefined)
let fkiInscriptionnotauthenticatedID: string; //Specify which Inscriptionnotauthenticated we want to display. (optional) (default to undefined)
let fkiInscriptiontempID: string; //Specify which Inscriptiontemp we want to display. (optional) (default to undefined)
let fkiAgentID: string; //Specify which Agent we want to display. (optional) (default to undefined)
let fkiBrokerID: string; //Specify which Broker we want to display. (optional) (default to undefined)
let fkiOtherincomeID: string; //Specify which Otherincome we want to display. (optional) (default to undefined)
let fkiRejectedoffertopurchaseID: string; //Specify which Rejectedoffertopurchase we want to display. (optional) (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.inscriptionchecklistGetAutocompleteV3(
    sSelector,
    fkiBuyercontractID,
    fkiInscriptionID,
    fkiInscriptionnotauthenticatedID,
    fkiInscriptiontempID,
    fkiAgentID,
    fkiBrokerID,
    fkiOtherincomeID,
    fkiRejectedoffertopurchaseID,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Inscriptionchecklist to return | defaults to undefined|
| **fkiBuyercontractID** | [**string**] | Specify which Buyercontract we want to display. | (optional) defaults to undefined|
| **fkiInscriptionID** | [**string**] | Specify which Inscription we want to display. | (optional) defaults to undefined|
| **fkiInscriptionnotauthenticatedID** | [**string**] | Specify which Inscriptionnotauthenticated we want to display. | (optional) defaults to undefined|
| **fkiInscriptiontempID** | [**string**] | Specify which Inscriptiontemp we want to display. | (optional) defaults to undefined|
| **fkiAgentID** | [**string**] | Specify which Agent we want to display. | (optional) defaults to undefined|
| **fkiBrokerID** | [**string**] | Specify which Broker we want to display. | (optional) defaults to undefined|
| **fkiOtherincomeID** | [**string**] | Specify which Otherincome we want to display. | (optional) defaults to undefined|
| **fkiRejectedoffertopurchaseID** | [**string**] | Specify which Rejectedoffertopurchase we want to display. | (optional) defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**InscriptionchecklistGetAutocompleteV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

