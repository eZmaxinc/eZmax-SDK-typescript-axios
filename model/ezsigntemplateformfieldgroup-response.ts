/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldgroupSignerrequirement } from './field-eezsigntemplateformfieldgroup-signerrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldgroupTooltipposition } from './field-eezsigntemplateformfieldgroup-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
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
    'sEzsigntemplateformfieldgroupDefaultvalue'?: string;
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
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsigntemplateformfieldgroupResponse
     */
    'eEzsigntemplateformfieldgroupTextvalidation'?: EnumTextvalidation;
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


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateformfieldgroupResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldgroupResponse
 */
export class DataObjectEzsigntemplateformfieldgroupResponse {
   pkiEzsigntemplateformfieldgroupID:number = 0
   fkiEzsigntemplatedocumentID:number = 0
   eEzsigntemplateformfieldgroupType:FieldEEzsigntemplateformfieldgroupType = 'Text'
   eEzsigntemplateformfieldgroupSignerrequirement:FieldEEzsigntemplateformfieldgroupSignerrequirement = 'All'
   sEzsigntemplateformfieldgroupLabel:string = ''
   iEzsigntemplateformfieldgroupStep:number = 0
   sEzsigntemplateformfieldgroupDefaultvalue?:string = undefined
   iEzsigntemplateformfieldgroupFilledmin:number = 0
   iEzsigntemplateformfieldgroupFilledmax:number = 0
   bEzsigntemplateformfieldgroupReadonly:boolean = false
   iEzsigntemplateformfieldgroupMaxlength?:number = undefined
   bEzsigntemplateformfieldgroupEncrypted?:boolean = undefined
   sEzsigntemplateformfieldgroupRegexp?:string = undefined
   eEzsigntemplateformfieldgroupTextvalidation?:EnumTextvalidation = undefined
   tEzsigntemplateformfieldgroupTooltip?:string = undefined
   eEzsigntemplateformfieldgroupTooltipposition?:FieldEEzsigntemplateformfieldgroupTooltipposition = undefined
}

/**
 * @export 
 * A EzsigntemplateformfieldgroupResponse Validation Object
 * @class ValidationObjectEzsigntemplateformfieldgroupResponse
 */
export class ValidationObjectEzsigntemplateformfieldgroupResponse {
   pkiEzsigntemplateformfieldgroupID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eEzsigntemplateformfieldgroupType = {
      type: 'enum',
      allowableValues: ['Text','Textarea','Dropdown','Radio','Checkbox','Number','Date'],
      required: true
   }
   eEzsigntemplateformfieldgroupSignerrequirement = {
      type: 'enum',
      allowableValues: ['All','One'],
      required: true
   }
   sEzsigntemplateformfieldgroupLabel = {
      type: 'string',
      required: true
   }
   iEzsigntemplateformfieldgroupStep = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzsigntemplateformfieldgroupDefaultvalue = {
      type: 'string',
      required: false
   }
   iEzsigntemplateformfieldgroupFilledmin = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplateformfieldgroupFilledmax = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsigntemplateformfieldgroupReadonly = {
      type: 'boolean',
      required: true
   }
   iEzsigntemplateformfieldgroupMaxlength = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   bEzsigntemplateformfieldgroupEncrypted = {
      type: 'boolean',
      required: false
   }
   sEzsigntemplateformfieldgroupRegexp = {
      type: 'string',
      pattern: '/^\^.*\$$|^$/',
      required: false
   }
   eEzsigntemplateformfieldgroupTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
      required: false
   }
   tEzsigntemplateformfieldgroupTooltip = {
      type: 'string',
      required: false
   }
   eEzsigntemplateformfieldgroupTooltipposition = {
      type: 'enum',
      allowableValues: ['TopLeft','TopCenter','TopRight','MiddleLeft','MiddleRight','BottomLeft','BottomCenter','BottomRight'],
      required: false
   }
} 


