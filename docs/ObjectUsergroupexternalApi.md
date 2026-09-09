# ObjectUsergroupexternalApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**usergroupexternalCreateObjectV1**](#usergroupexternalcreateobjectv1) | **POST** /1/object/usergroupexternal | Create a new Usergroupexternal|
|[**usergroupexternalDeleteObjectV1**](#usergroupexternaldeleteobjectv1) | **DELETE** /1/object/usergroupexternal/{pkiUsergroupexternalID} | Delete an existing Usergroupexternal|
|[**usergroupexternalEditObjectV1**](#usergroupexternaleditobjectv1) | **PUT** /1/object/usergroupexternal/{pkiUsergroupexternalID} | Edit an existing Usergroupexternal|
|[**usergroupexternalGetAutocompleteV2**](#usergroupexternalgetautocompletev2) | **GET** /2/object/usergroupexternal/getAutocomplete/{sSelector} | Retrieve Usergroupexternals and IDs|
|[**usergroupexternalGetListV1**](#usergroupexternalgetlistv1) | **GET** /1/object/usergroupexternal/getList | Retrieve Usergroupexternal list|
|[**usergroupexternalGetObjectV2**](#usergroupexternalgetobjectv2) | **GET** /2/object/usergroupexternal/{pkiUsergroupexternalID} | Retrieve an existing Usergroupexternal|
|[**usergroupexternalGetUsergroupexternalmembershipsV1**](#usergroupexternalgetusergroupexternalmembershipsv1) | **GET** /1/object/usergroupexternal/{pkiUsergroupexternalID}/getUsergroupexternalmemberships | Retrieve an existing Usergroupexternal\&#39;s Usergroupexternalmemberships|
|[**usergroupexternalGetUsergroupsV1**](#usergroupexternalgetusergroupsv1) | **GET** /1/object/usergroupexternal/{pkiUsergroupexternalID}/getUsergroups | Get Usergroupexternal\&#39;s Usergroups|

# **usergroupexternalCreateObjectV1**
> UsergroupexternalCreateObjectV1Response usergroupexternalCreateObjectV1(usergroupexternalCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration,
    UsergroupexternalCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let usergroupexternalCreateObjectV1Request: UsergroupexternalCreateObjectV1Request; //

const { status, data } = await apiInstance.usergroupexternalCreateObjectV1(
    usergroupexternalCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupexternalCreateObjectV1Request** | **UsergroupexternalCreateObjectV1Request**|  | |


### Return type

**UsergroupexternalCreateObjectV1Response**

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

# **usergroupexternalDeleteObjectV1**
> UsergroupexternalDeleteObjectV1Response usergroupexternalDeleteObjectV1()



### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let pkiUsergroupexternalID: number; //The unique ID of the Usergroupexternal (default to undefined)

const { status, data } = await apiInstance.usergroupexternalDeleteObjectV1(
    pkiUsergroupexternalID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupexternalID** | [**number**] | The unique ID of the Usergroupexternal | defaults to undefined|


### Return type

**UsergroupexternalDeleteObjectV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usergroupexternalEditObjectV1**
> UsergroupexternalEditObjectV1Response usergroupexternalEditObjectV1(usergroupexternalEditObjectV1Request)



### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration,
    UsergroupexternalEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let pkiUsergroupexternalID: number; //The unique ID of the Usergroupexternal (default to undefined)
let usergroupexternalEditObjectV1Request: UsergroupexternalEditObjectV1Request; //

const { status, data } = await apiInstance.usergroupexternalEditObjectV1(
    pkiUsergroupexternalID,
    usergroupexternalEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupexternalEditObjectV1Request** | **UsergroupexternalEditObjectV1Request**|  | |
| **pkiUsergroupexternalID** | [**number**] | The unique ID of the Usergroupexternal | defaults to undefined|


### Return type

**UsergroupexternalEditObjectV1Response**

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

# **usergroupexternalGetAutocompleteV2**
> UsergroupexternalGetAutocompleteV2Response usergroupexternalGetAutocompleteV2()

Get the list of Usergroupexternal to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let sSelector: 'All'; //The type of Usergroupexternals to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.usergroupexternalGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Usergroupexternals to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**UsergroupexternalGetAutocompleteV2Response**

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

# **usergroupexternalGetListV1**
> UsergroupexternalGetListV1Response usergroupexternalGetListV1()



### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let eOrderBy: 'pkiUsergroupexternalID_ASC' | 'pkiUsergroupexternalID_DESC' | 'sUsergroupexternalName_ASC' | 'sUsergroupexternalName_DESC' | 'sUsergroupexternalID_ASC' | 'sUsergroupexternalID_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.usergroupexternalGetListV1(
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
| **eOrderBy** | [**&#39;pkiUsergroupexternalID_ASC&#39; | &#39;pkiUsergroupexternalID_DESC&#39; | &#39;sUsergroupexternalName_ASC&#39; | &#39;sUsergroupexternalName_DESC&#39; | &#39;sUsergroupexternalID_ASC&#39; | &#39;sUsergroupexternalID_DESC&#39;**]**Array<&#39;pkiUsergroupexternalID_ASC&#39; &#124; &#39;pkiUsergroupexternalID_DESC&#39; &#124; &#39;sUsergroupexternalName_ASC&#39; &#124; &#39;sUsergroupexternalName_DESC&#39; &#124; &#39;sUsergroupexternalID_ASC&#39; &#124; &#39;sUsergroupexternalID_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**UsergroupexternalGetListV1Response**

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

# **usergroupexternalGetObjectV2**
> UsergroupexternalGetObjectV2Response usergroupexternalGetObjectV2()



### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let pkiUsergroupexternalID: number; //The unique ID of the Usergroupexternal (default to undefined)

const { status, data } = await apiInstance.usergroupexternalGetObjectV2(
    pkiUsergroupexternalID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupexternalID** | [**number**] | The unique ID of the Usergroupexternal | defaults to undefined|


### Return type

**UsergroupexternalGetObjectV2Response**

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

# **usergroupexternalGetUsergroupexternalmembershipsV1**
> UsergroupexternalGetUsergroupexternalmembershipsV1Response usergroupexternalGetUsergroupexternalmembershipsV1()


### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let pkiUsergroupexternalID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupexternalGetUsergroupexternalmembershipsV1(
    pkiUsergroupexternalID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupexternalID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupexternalGetUsergroupexternalmembershipsV1Response**

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

# **usergroupexternalGetUsergroupsV1**
> UsergroupexternalGetUsergroupsV1Response usergroupexternalGetUsergroupsV1()


### Example

```typescript
import {
    ObjectUsergroupexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupexternalApi(configuration);

let pkiUsergroupexternalID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupexternalGetUsergroupsV1(
    pkiUsergroupexternalID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupexternalID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupexternalGetUsergroupsV1Response**

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

