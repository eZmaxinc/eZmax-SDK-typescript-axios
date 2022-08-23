/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CustomDropdownElementResponseCompound } from './custom-dropdown-element-response-compound';
import { EzsigntemplateformfieldResponseCompound } from './ezsigntemplateformfield-response-compound';
import { EzsigntemplateformfieldgroupsignerResponseCompound } from './ezsigntemplateformfieldgroupsigner-response-compound';

/**
 * 
 * @export
 * @interface EzsigntemplateformfieldgroupResponseCompoundAllOf
 */
export interface EzsigntemplateformfieldgroupResponseCompoundAllOf {
    /**
     * 
     * @type {Array<EzsigntemplateformfieldgroupsignerResponseCompound>}
     * @memberof EzsigntemplateformfieldgroupResponseCompoundAllOf
     */
    'a_objEzsigntemplateformfieldgroupsigner': Array<EzsigntemplateformfieldgroupsignerResponseCompound>;
    /**
     * 
     * @type {Array<CustomDropdownElementResponseCompound>}
     * @memberof EzsigntemplateformfieldgroupResponseCompoundAllOf
     */
    'a_objDropdownElement'?: Array<CustomDropdownElementResponseCompound>;
    /**
     * 
     * @type {Array<EzsigntemplateformfieldResponseCompound>}
     * @memberof EzsigntemplateformfieldgroupResponseCompoundAllOf
     */
    'a_objEzsigntemplateformfield': Array<EzsigntemplateformfieldResponseCompound>;
}

