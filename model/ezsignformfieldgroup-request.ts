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


import { FieldEEzsignformfieldgroupSignerrequirement } from './field-eezsignformfieldgroup-signerrequirement';
import { FieldEEzsignformfieldgroupTooltipposition } from './field-eezsignformfieldgroup-tooltipposition';
import { FieldEEzsignformfieldgroupType } from './field-eezsignformfieldgroup-type';

/**
 * An Ezsignformfieldgroup Object
 * @export
 * @interface EzsignformfieldgroupRequest
 */
export interface EzsignformfieldgroupRequest {
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupRequest
     */
    'pkiEzsignformfieldgroupID'?: number;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignformfieldgroupRequest
     */
    'fkiEzsigndocumentID': number;
    /**
     * 
     * @type {FieldEEzsignformfieldgroupType}
     * @memberof EzsignformfieldgroupRequest
     */
    'eEzsignformfieldgroupType': FieldEEzsignformfieldgroupType;
    /**
     * 
     * @type {FieldEEzsignformfieldgroupSignerrequirement}
     * @memberof EzsignformfieldgroupRequest
     */
    'eEzsignformfieldgroupSignerrequirement': FieldEEzsignformfieldgroupSignerrequirement;
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupRequest
     */
    'sEzsignformfieldgroupLabel': string;
    /**
     * The step when the Ezsignsigner will be invited to fill the form fields
     * @type {number}
     * @memberof EzsignformfieldgroupRequest
     */
    'iEzsignformfieldgroupStep': number;
    /**
     * The default value for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupRequest
     */
    'sEzsignformfieldgroupDefaultvalue': string;
    /**
     * The minimum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupRequest
     */
    'iEzsignformfieldgroupFilledmin': number;
    /**
     * The maximum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupRequest
     */
    'iEzsignformfieldgroupFilledmax': number;
    /**
     * Whether the Ezsignformfieldgroup is read only or not.
     * @type {boolean}
     * @memberof EzsignformfieldgroupRequest
     */
    'bEzsignformfieldgroupReadonly': boolean;
    /**
     * The maximum length for the value in the Ezsignformfieldgroup  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {number}
     * @memberof EzsignformfieldgroupRequest
     */
    'iEzsignformfieldgroupMaxlength'?: number;
    /**
     * Whether the Ezsignformfieldgroup is encrypted in the database or not. Encrypted values are not displayed on the Ezsigndocument. This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {boolean}
     * @memberof EzsignformfieldgroupRequest
     */
    'bEzsignformfieldgroupEncrypted'?: boolean;
    /**
     * A regular expression to indicate what values are acceptable for the Ezsignformfieldgroup.  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsignformfieldgroupRequest
     */
    'sEzsignformfieldgroupRegexp'?: string;
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupRequest
     */
    'tEzsignformfieldgroupTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsignformfieldgroupTooltipposition}
     * @memberof EzsignformfieldgroupRequest
     */
    'eEzsignformfieldgroupTooltipposition'?: FieldEEzsignformfieldgroupTooltipposition;
}

