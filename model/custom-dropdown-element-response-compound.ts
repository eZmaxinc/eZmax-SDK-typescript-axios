/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CustomDropdownElementResponse } from './custom-dropdown-element-response';

/**
 * @type CustomDropdownElementResponseCompound
 * A Generic DropdownElement Object and children to create a complete structure
 * @export
 */
/*export type CustomDropdownElementResponseCompound = CustomDropdownElementResponse;*/
export interface CustomDropdownElementResponseCompound {
    /**
     * The Description of the element
     * @type {string}
     * @memberof CustomDropdownElementResponseCompound
     */
    sLabel:string 
    /**
     * The Value of the element
     * @type {string}
     * @memberof CustomDropdownElementResponseCompound
     */
    sValue:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomDropdownElementResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomDropdownElementResponseCompound
 */
export class DataObjectCustomDropdownElementResponseCompound {
    sLabel:string = ''
    sValue:string = ''
}

/**
 * @export 
 * A CustomDropdownElementResponseCompound Validation Object
 * @class ValidationObjectCustomDropdownElementResponseCompound
 */
export class ValidationObjectCustomDropdownElementResponseCompound {
   sLabel = {
      type: 'string',
      required: true
   }
   sValue = {
      type: 'string',
      required: true
   }
} 


