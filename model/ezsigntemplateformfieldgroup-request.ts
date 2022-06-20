/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FieldEEzsigntemplateformfieldgroupSignerrequirement } from './field-eezsigntemplateformfieldgroup-signerrequirement';
import { FieldEEzsigntemplateformfieldgroupTooltipposition } from './field-eezsigntemplateformfieldgroup-tooltipposition';
import { FieldEEzsigntemplateformfieldgroupType } from './field-eezsigntemplateformfieldgroup-type';

/**
 * A Ezsigntemplateformfieldgroup Object
 * @export
 * @interface EzsigntemplateformfieldgroupRequest
 */
export interface EzsigntemplateformfieldgroupRequest {
    /**
     * The unique ID of the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'pkiEzsigntemplateformfieldgroupID'?: number;
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'fkiEzsigntemplatedocumentID': number;
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldgroupType}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'eEzsigntemplateformfieldgroupType': FieldEEzsigntemplateformfieldgroupType;
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldgroupSignerrequirement}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'eEzsigntemplateformfieldgroupSignerrequirement': FieldEEzsigntemplateformfieldgroupSignerrequirement;
    /**
     * The Label for the Ezsigntemplateformfieldgroup
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'sEzsigntemplateformfieldgroupLabel': string;
    /**
     * The step when the Ezsigntemplatesigner will be invited to fill the form fields
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'iEzsigntemplateformfieldgroupStep': number;
    /**
     * The default value for the Ezsigntemplateformfieldgroup
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'sEzsigntemplateformfieldgroupDefaultvalue': string;
    /**
     * The minimum number of Ezsigntemplateformfield that must be filled in the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'iEzsigntemplateformfieldgroupFilledmin': number;
    /**
     * The maximum number of Ezsigntemplateformfield that must be filled in the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'iEzsigntemplateformfieldgroupFilledmax': number;
    /**
     * Whether the Ezsigntemplateformfieldgroup is read only or not.
     * @type {boolean}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'bEzsigntemplateformfieldgroupReadonly': boolean;
    /**
     * The maximum length for the value in the Ezsigntemplateformfieldgroup  This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea**
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'iEzsigntemplateformfieldgroupMaxlength'?: number;
    /**
     * Whether the Ezsigntemplateformfieldgroup is encrypted in the database or not. Encrypted values are not displayed on the Ezsigndocument. This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'bEzsigntemplateformfieldgroupEncrypted'?: boolean;
    /**
     * A regular expression to indicate what values are acceptable for the Ezsigntemplateformfieldgroup.  This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'sEzsigntemplateformfieldgroupRegexp'?: string;
    /**
     * A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplateformfieldgroup
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'tEzsigntemplateformfieldgroupTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldgroupTooltipposition}
     * @memberof EzsigntemplateformfieldgroupRequest
     */
    'eEzsigntemplateformfieldgroupTooltipposition'?: FieldEEzsigntemplateformfieldgroupTooltipposition;
}
