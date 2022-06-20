/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
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
 * @interface EzsigntemplateformfieldgroupResponse
 */
export interface EzsigntemplateformfieldgroupResponse {
    /**
     * The unique ID of the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'pkiEzsigntemplateformfieldgroupID': number;
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'fkiEzsigntemplatedocumentID': number;
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldgroupType}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'eEzsigntemplateformfieldgroupType': FieldEEzsigntemplateformfieldgroupType;
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldgroupSignerrequirement}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'eEzsigntemplateformfieldgroupSignerrequirement': FieldEEzsigntemplateformfieldgroupSignerrequirement;
    /**
     * The Label for the Ezsigntemplateformfieldgroup
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'sEzsigntemplateformfieldgroupLabel': string;
    /**
     * The step when the Ezsigntemplatesigner will be invited to fill the form fields
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'iEzsigntemplateformfieldgroupStep': number;
    /**
     * The default value for the Ezsigntemplateformfieldgroup
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'sEzsigntemplateformfieldgroupDefaultvalue': string;
    /**
     * The minimum number of Ezsigntemplateformfield that must be filled in the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'iEzsigntemplateformfieldgroupFilledmin': number;
    /**
     * The maximum number of Ezsigntemplateformfield that must be filled in the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'iEzsigntemplateformfieldgroupFilledmax': number;
    /**
     * Whether the Ezsigntemplateformfieldgroup is read only or not.
     * @type {boolean}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'bEzsigntemplateformfieldgroupReadonly': boolean;
    /**
     * The maximum length for the value in the Ezsigntemplateformfieldgroup  This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea**
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'iEzsigntemplateformfieldgroupMaxlength'?: number;
    /**
     * Whether the Ezsigntemplateformfieldgroup is encrypted in the database or not. Encrypted values are not displayed on the Ezsigndocument. This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'bEzsigntemplateformfieldgroupEncrypted'?: boolean;
    /**
     * A regular expression to indicate what values are acceptable for the Ezsigntemplateformfieldgroup.  This can only be set if eEzsigntemplateformfieldgroupType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'sEzsigntemplateformfieldgroupRegexp'?: string;
    /**
     * A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplateformfieldgroup
     * @type {string}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'tEzsigntemplateformfieldgroupTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldgroupTooltipposition}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'eEzsigntemplateformfieldgroupTooltipposition'?: FieldEEzsigntemplateformfieldgroupTooltipposition;
}

