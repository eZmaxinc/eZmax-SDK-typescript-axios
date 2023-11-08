/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CompanyAutocompleteElementResponse } from './company-autocomplete-element-response';

/**
 * Payload for POST /2/object/company/getAutocomplete
 * @export
 * @interface CompanyGetAutocompleteV2ResponseMPayload
 */
export interface CompanyGetAutocompleteV2ResponseMPayload {
    /**
     * An array of Company autocomplete element response.
     * @type {Array<CompanyAutocompleteElementResponse>}
     * @memberof CompanyGetAutocompleteV2ResponseMPayload
     */
    'a_objCompany': Array<CompanyAutocompleteElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CompanyGetAutocompleteV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCompanyGetAutocompleteV2ResponseMPayload
 */
export class DataObjectCompanyGetAutocompleteV2ResponseMPayload {
   a_objCompany:Array<CompanyAutocompleteElementResponse> = []
}

/**
 * @export 
 * A CompanyGetAutocompleteV2ResponseMPayload Validation Object
 * @class ValidationObjectCompanyGetAutocompleteV2ResponseMPayload
 */
export class ValidationObjectCompanyGetAutocompleteV2ResponseMPayload {
   a_objCompany = {
      type: 'array',
      required: true
   }
} 

