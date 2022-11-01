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
import { CustomDropdownElementRequestCompound } from './custom-dropdown-element-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldRequestCompound } from './ezsigntemplateformfield-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupsignerRequestCompound } from './ezsigntemplateformfieldgroupsigner-request-compound';

import { DefaultObject } from '../base'

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
 * A EzsigntemplateformfieldgroupRequestCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateformfieldgroupRequestCompoundAllOf
 */
export class DefaultObjectEzsigntemplateformfieldgroupRequestCompoundAllOf extends DefaultObject {
   a_objEzsigntemplateformfieldgroupsigner:Array<EzsigntemplateformfieldgroupsignerRequestCompound> = []
   a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> = undefined
   a_objEzsigntemplateformfield:Array<EzsigntemplateformfieldRequestCompound> = []
}


