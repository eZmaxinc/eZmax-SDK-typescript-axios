# ObjectSupplyApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**supplyCreateObjectV1**](#supplycreateobjectv1) | **POST** /1/object/supply | Create a new Supply|
|[**supplyDeleteObjectV1**](#supplydeleteobjectv1) | **DELETE** /1/object/supply/{pkiSupplyID} | Delete an existing Supply|
|[**supplyEditObjectV1**](#supplyeditobjectv1) | **PUT** /1/object/supply/{pkiSupplyID} | Edit an existing Supply|
|[**supplyGetAutocompleteV2**](#supplygetautocompletev2) | **GET** /2/object/supply/getAutocomplete/{sSelector} | Retrieve Supplys and IDs|
|[**supplyGetListV1**](#supplygetlistv1) | **GET** /1/object/supply/getList | Retrieve Supply list|
|[**supplyGetObjectV2**](#supplygetobjectv2) | **GET** /2/object/supply/{pkiSupplyID} | Retrieve an existing Supply|

# **supplyCreateObjectV1**
> SupplyCreateObjectV1Response supplyCreateObjectV1(supplyCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectSupplyApi,
    Configuration,
    SupplyCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplyApi(configuration);

let supplyCreateObjectV1Request: SupplyCreateObjectV1Request; //

const { status, data } = await apiInstance.supplyCreateObjectV1(
    supplyCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **supplyCreateObjectV1Request** | **SupplyCreateObjectV1Request**|  | |


### Return type

**SupplyCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **supplyDeleteObjectV1**
> SupplyDeleteObjectV1Response supplyDeleteObjectV1()



### Example

```typescript
import {
    ObjectSupplyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplyApi(configuration);

let pkiSupplyID: number; //The unique ID of the Supply (default to undefined)

const { status, data } = await apiInstance.supplyDeleteObjectV1(
    pkiSupplyID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSupplyID** | [**number**] | The unique ID of the Supply | defaults to undefined|


### Return type

**SupplyDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **supplyEditObjectV1**
> SupplyEditObjectV1Response supplyEditObjectV1(supplyEditObjectV1Request)



### Example

```typescript
import {
    ObjectSupplyApi,
    Configuration,
    SupplyEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplyApi(configuration);

let pkiSupplyID: number; //The unique ID of the Supply (default to undefined)
let supplyEditObjectV1Request: SupplyEditObjectV1Request; //

const { status, data } = await apiInstance.supplyEditObjectV1(
    pkiSupplyID,
    supplyEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **supplyEditObjectV1Request** | **SupplyEditObjectV1Request**|  | |
| **pkiSupplyID** | [**number**] | The unique ID of the Supply | defaults to undefined|


### Return type

**SupplyEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **supplyGetAutocompleteV2**
> SupplyGetAutocompleteV2Response supplyGetAutocompleteV2()

Get the list of Supply to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectSupplyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplyApi(configuration);

let sSelector: 'All'; //The type of Supplys to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.supplyGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Supplys to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**SupplyGetAutocompleteV2Response**

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

# **supplyGetListV1**
> SupplyGetListV1Response supplyGetListV1()



### Example

```typescript
import {
    ObjectSupplyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplyApi(configuration);

let eOrderBy: 'pkiSupplyID_ASC' | 'pkiSupplyID_DESC' | 'fkiGlaccountID_ASC' | 'fkiGlaccountID_DESC' | 'fkiGlaccountcontainerID_ASC' | 'fkiGlaccountcontainerID_DESC' | 'fkiVariableexpenseID_ASC' | 'fkiVariableexpenseID_DESC' | 'sSupplyCode_ASC' | 'sSupplyCode_DESC' | 'sSupplyDescriptionX_ASC' | 'sSupplyDescriptionX_DESC' | 'dSupplyUnitprice_ASC' | 'dSupplyUnitprice_DESC' | 'bSupplyIsactive_ASC' | 'bSupplyIsactive_DESC' | 'bSupplyVariableprice_ASC' | 'bSupplyVariableprice_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.supplyGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiSupplyID_ASC&#39; | &#39;pkiSupplyID_DESC&#39; | &#39;fkiGlaccountID_ASC&#39; | &#39;fkiGlaccountID_DESC&#39; | &#39;fkiGlaccountcontainerID_ASC&#39; | &#39;fkiGlaccountcontainerID_DESC&#39; | &#39;fkiVariableexpenseID_ASC&#39; | &#39;fkiVariableexpenseID_DESC&#39; | &#39;sSupplyCode_ASC&#39; | &#39;sSupplyCode_DESC&#39; | &#39;sSupplyDescriptionX_ASC&#39; | &#39;sSupplyDescriptionX_DESC&#39; | &#39;dSupplyUnitprice_ASC&#39; | &#39;dSupplyUnitprice_DESC&#39; | &#39;bSupplyIsactive_ASC&#39; | &#39;bSupplyIsactive_DESC&#39; | &#39;bSupplyVariableprice_ASC&#39; | &#39;bSupplyVariableprice_DESC&#39;**]**Array<&#39;pkiSupplyID_ASC&#39; &#124; &#39;pkiSupplyID_DESC&#39; &#124; &#39;fkiGlaccountID_ASC&#39; &#124; &#39;fkiGlaccountID_DESC&#39; &#124; &#39;fkiGlaccountcontainerID_ASC&#39; &#124; &#39;fkiGlaccountcontainerID_DESC&#39; &#124; &#39;fkiVariableexpenseID_ASC&#39; &#124; &#39;fkiVariableexpenseID_DESC&#39; &#124; &#39;sSupplyCode_ASC&#39; &#124; &#39;sSupplyCode_DESC&#39; &#124; &#39;sSupplyDescriptionX_ASC&#39; &#124; &#39;sSupplyDescriptionX_DESC&#39; &#124; &#39;dSupplyUnitprice_ASC&#39; &#124; &#39;dSupplyUnitprice_DESC&#39; &#124; &#39;bSupplyIsactive_ASC&#39; &#124; &#39;bSupplyIsactive_DESC&#39; &#124; &#39;bSupplyVariableprice_ASC&#39; &#124; &#39;bSupplyVariableprice_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**SupplyGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **supplyGetObjectV2**
> SupplyGetObjectV2Response supplyGetObjectV2()



### Example

```typescript
import {
    ObjectSupplyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplyApi(configuration);

let pkiSupplyID: number; //The unique ID of the Supply (default to undefined)

const { status, data } = await apiInstance.supplyGetObjectV2(
    pkiSupplyID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSupplyID** | [**number**] | The unique ID of the Supply | defaults to undefined|


### Return type

**SupplyGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

