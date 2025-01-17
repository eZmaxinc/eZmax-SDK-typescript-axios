/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CustomDropdownElementRequest } from './custom-dropdown-element-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateformfieldRequestCompound } from './ezsigntemplateformfield-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateformfieldgroupRequest } from './ezsigntemplateformfieldgroup-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateformfieldgroupsignerRequest } from './ezsigntemplateformfieldgroupsigner-request';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateformfieldgroupSignerrequirement } from './field-eezsigntemplateformfieldgroup-signerrequirement';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateformfieldgroupTooltipposition } from './field-eezsigntemplateformfieldgroup-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateformfieldgroupType } from './field-eezsigntemplateformfieldgroup-type';

/**
 * @type EzsigntemplateformfieldgroupRequestCompound
 * A Ezsigntemplateformfieldgroup Object and children
 * @export
 */
/*export type EzsigntemplateformfieldgroupRequestCompound = EzsigntemplateformfieldgroupRequest;*/
export interface EzsigntemplateformfieldgroupRequestCompound {
    /**
     * 
     * @type {Array<EzsigntemplateformfieldgroupsignerRequestCompound>}
     * @memberof EzsigntemplateformfieldgroupRequestCompound
     */
    a_objEzsigntemplateformfieldgroupsigner:Array<EzsigntemplateformfieldgroupsignerRequestCompound> 
    /**
     * 
     * @type {Array<CustomDropdownElementRequestCompound>}
     * @memberof EzsigntemplateformfieldgroupRequestCompound
     */
    a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> 
    /**
     * 
     * @type {Array<EzsigntemplateformfieldRequestCompound>}
     * @memberof EzsigntemplateformfieldgroupRequestCompound
     */
    a_objEzsigntemplateformfield:Array<EzsigntemplateformfieldRequestCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateformfieldgroupRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupRequestCompound
 */
export class DataObjectEzsigntemplateformfieldgroupRequestCompound {
    a_objEzsigntemplateformfieldgroupsigner:Array<EzsigntemplateformfieldgroupsignerRequestCompound> = []
    a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> = undefined
    a_objEzsigntemplateformfield:Array<EzsigntemplateformfieldRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupRequestCompound
 */
export class ValidationObjectEzsigntemplateformfieldgroupRequestCompound {
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


