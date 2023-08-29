/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignformfielderrortestResponse } from './custom-ezsignformfielderrortest-response';

/**
 * A Custom Ezsignformfield Object to contain an error list
 * @export
 * @interface CustomEzsignformfielderrorResponse
 */
export interface CustomEzsignformfielderrorResponse {
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof CustomEzsignformfielderrorResponse
     */
    'sEzsignformfieldLabel': string;
    /**
     * 
     * @type {Array<CustomEzsignformfielderrortestResponse>}
     * @memberof CustomEzsignformfielderrorResponse
     */
    'a_objEzsignformfielderrortest': Array<CustomEzsignformfielderrortestResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignformfielderrorResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignformfielderrorResponse
 */
export class DataObjectCustomEzsignformfielderrorResponse {
   sEzsignformfieldLabel:string = ''
   a_objEzsignformfielderrortest:Array<CustomEzsignformfielderrortestResponse> = []
}

/**
 * @export 
 * A CustomEzsignformfielderrorResponse Validation Object
 * @class ValidationObjectCustomEzsignformfielderrorResponse
 */
export class ValidationObjectCustomEzsignformfielderrorResponse {
   sEzsignformfieldLabel = {
      type: 'string',
      required: true
   }
   a_objEzsignformfielderrortest = {
      type: 'array',
      required: true
   }
} 


