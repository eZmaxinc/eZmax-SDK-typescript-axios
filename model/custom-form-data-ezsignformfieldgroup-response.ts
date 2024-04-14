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
import { CustomFormDataEzsignformfieldResponse } from './custom-form-data-ezsignformfield-response';

/**
 * An FormDataSigner->Ezsignformfieldgroup Object and children to create a complete structure
 * @export
 * @interface CustomFormDataEzsignformfieldgroupResponse
 */
export interface CustomFormDataEzsignformfieldgroupResponse {
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof CustomFormDataEzsignformfieldgroupResponse
     */
    /*'sEzsignformfieldgroupLabel': string;*/
    'sEzsignformfieldgroupLabel': string;
    /**
     * 
     * @type {Array<CustomFormDataEzsignformfieldResponse>}
     * @memberof CustomFormDataEzsignformfieldgroupResponse
     */
    /*'a_objEzsignformfield': Array<CustomFormDataEzsignformfieldResponse>;*/
    'a_objEzsignformfield': Array<CustomFormDataEzsignformfieldResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomFormDataEzsignformfieldgroupResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomFormDataEzsignformfieldgroupResponse
 */
export class DataObjectCustomFormDataEzsignformfieldgroupResponse {
   sEzsignformfieldgroupLabel:string = ''
   a_objEzsignformfield:Array<CustomFormDataEzsignformfieldResponse> = []
}

/**
 * @export 
 * A CustomFormDataEzsignformfieldgroupResponse Validation Object
 * @class ValidationObjectCustomFormDataEzsignformfieldgroupResponse
 */
export class ValidationObjectCustomFormDataEzsignformfieldgroupResponse {
   sEzsignformfieldgroupLabel = {
      type: 'string',
      required: true
   }
   a_objEzsignformfield = {
      type: 'array',
      required: true
   }
} 


