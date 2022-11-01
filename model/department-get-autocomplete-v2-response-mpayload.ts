/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { DepartmentAutocompleteElementResponse } from './department-autocomplete-element-response';

import { DefaultObject } from '../base'

/**
 * Payload for POST /2/object/department/getAutocomplete
 * @export
 * @interface DepartmentGetAutocompleteV2ResponseMPayload
 */
export interface DepartmentGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Department autocomplete element response.
     * @type {Array<DepartmentAutocompleteElementResponse>}
     * @memberof DepartmentGetAutocompleteV2ResponseMPayload
     */
    'a_objDepartment': Array<DepartmentAutocompleteElementResponse>;
}
/**
 * A DepartmentGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectDepartmentGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectDepartmentGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objDepartment:Array<DepartmentAutocompleteElementResponse> = []
}


