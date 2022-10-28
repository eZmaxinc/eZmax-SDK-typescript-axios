/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * An Ezsignformfield Object
 * @export
 * @interface CustomFormDataEzsignformfieldResponse
 */
export interface CustomFormDataEzsignformfieldResponse {
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof CustomFormDataEzsignformfieldResponse
     */
    'sEzsignformfieldLabel': string;
    /**
     * The value for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is Checkbox or Radio
     * @type {string}
     * @memberof CustomFormDataEzsignformfieldResponse
     */
    'sEzsignformfieldValue': string;
}
/**
 * A CustomFormDataEzsignformfieldResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomFormDataEzsignformfieldResponse
 */
export class DefaultObjectCustomFormDataEzsignformfieldResponse extends DefaultObject {
   sEzsignformfieldLabel:string = ''
   sEzsignformfieldValue:string = ''
}


