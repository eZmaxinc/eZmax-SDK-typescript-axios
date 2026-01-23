# ObjectCustomerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**customerGetAutocompleteV2**](#customergetautocompletev2) | **GET** /2/object/customer/getAutocomplete/{sSelector} | Retrieve Customers and IDs|
|[**customerGetObjectV2**](#customergetobjectv2) | **GET** /2/object/customer/{pkiCustomerID} | Retrieve an existing Customer|
|[**customerImportIntoEDMV1**](#customerimportintoedmv1) | **POST** /1/object/customer/{pkiCustomerID}/importIntoEDM | Import attachments into the Customer|

# **customerGetAutocompleteV2**
> CustomerGetAutocompleteV2Response customerGetAutocompleteV2()

Get the list of Customer to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let sSelector: 'All'; //The type of Customers to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.customerGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Customers to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**CustomerGetAutocompleteV2Response**

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

# **customerGetObjectV2**
> CustomerGetObjectV2Response customerGetObjectV2()



### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let pkiCustomerID: number; //The unique ID of the Customer (default to undefined)

const { status, data } = await apiInstance.customerGetObjectV2(
    pkiCustomerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCustomerID** | [**number**] | The unique ID of the Customer | defaults to undefined|


### Return type

**CustomerGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **customerImportIntoEDMV1**
> CustomerImportIntoEDMV1Response customerImportIntoEDMV1(customerImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration,
    CustomerImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let pkiCustomerID: number; // (default to undefined)
let customerImportIntoEDMV1Request: CustomerImportIntoEDMV1Request; //

const { status, data } = await apiInstance.customerImportIntoEDMV1(
    pkiCustomerID,
    customerImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **customerImportIntoEDMV1Request** | **CustomerImportIntoEDMV1Request**|  | |
| **pkiCustomerID** | [**number**] |  | defaults to undefined|


### Return type

**CustomerImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

