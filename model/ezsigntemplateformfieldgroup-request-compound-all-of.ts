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
import { CustomDropdownElementRequestCompound } from './custom-dropdown-element-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldRequestCompound } from './ezsigntemplateformfield-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupsignerRequestCompound } from './ezsigntemplateformfieldgroupsigner-request-compound';

/**
 * 
 * @export
 * @interface EzsigntemplateformfieldgroupRequestCompoundAllOf
 */
export interface EzsigntemplateformfieldgroupRequestCompoundAllOf {
    /**
     * 
     * @type {Array<EzsigntemplateformfieldgroupsignerRequestCompound>}
     * @memberof EzsigntemplateformfieldgroupRequestCompoundAllOf
     */
    'a_objEzsigntemplateformfieldgroupsigner': Array<EzsigntemplateformfieldgroupsignerRequestCompound>;
    /**
     * 
     * @type {Array<CustomDropdownElementRequestCompound>}
     * @memberof EzsigntemplateformfieldgroupRequestCompoundAllOf
     */
    'a_objDropdownElement'?: Array<CustomDropdownElementRequestCompound>;
    /**
     * 
     * @type {Array<EzsigntemplateformfieldRequestCompound>}
     * @memberof EzsigntemplateformfieldgroupRequestCompoundAllOf
     */
    'a_objEzsigntemplateformfield': Array<EzsigntemplateformfieldRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateformfieldgroupRequestCompoundAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupRequestCompoundAllOf
 */
export class DataObjectEzsigntemplateformfieldgroupRequestCompoundAllOf {
   a_objEzsigntemplateformfieldgroupsigner:Array<EzsigntemplateformfieldgroupsignerRequestCompound> = []
   a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> = undefined
   a_objEzsigntemplateformfield:Array<EzsigntemplateformfieldRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupRequestCompoundAllOf Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupRequestCompoundAllOf
 */
export class ValidationObjectEzsigntemplateformfieldgroupRequestCompoundAllOf {
   a_objEzsigntemplateformfieldgroupsigner = {
      type: 'array',
      required: true
   }
   a_objDropdownElement = {
      type: 'array',
      required: false
   }
   a_objEzsigntemplateformfield = {
      type: 'array',
      required: true
   }
} 


