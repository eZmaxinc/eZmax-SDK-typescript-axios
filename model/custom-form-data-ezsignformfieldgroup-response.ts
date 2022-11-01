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
import { CustomFormDataEzsignformfieldResponse } from './custom-form-data-ezsignformfield-response';

import { DefaultObject } from '../base'

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
    'sEzsignformfieldgroupLabel': string;
    /**
     * 
     * @type {Array<CustomFormDataEzsignformfieldResponse>}
     * @memberof CustomFormDataEzsignformfieldgroupResponse
     */
    'a_objEzsignformfield': Array<CustomFormDataEzsignformfieldResponse>;
}
/**
 * A CustomFormDataEzsignformfieldgroupResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomFormDataEzsignformfieldgroupResponse
 */
export class DefaultObjectCustomFormDataEzsignformfieldgroupResponse extends DefaultObject {
   sEzsignformfieldgroupLabel:string = ''
   a_objEzsignformfield:Array<CustomFormDataEzsignformfieldResponse> = []
}


