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
import { CustomDropdownElementRequestCompound } from './custom-dropdown-element-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldRequestCompound } from './ezsignformfield-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupRequest } from './ezsignformfieldgroup-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupsignerRequestCompound } from './ezsignformfieldgroupsigner-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignformfieldgroupSignerrequirement } from './field-eezsignformfieldgroup-signerrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignformfieldgroupTooltipposition } from './field-eezsignformfieldgroup-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignformfieldgroupType } from './field-eezsignformfieldgroup-type';

/**
 * @type EzsignformfieldgroupRequestCompound
 * An Ezsignformfieldgroup Object and children to create a complete structure
 * @export
 */
/** export type EzsignformfieldgroupRequestCompound = EzsignformfieldgroupRequest; */
export interface EzsignformfieldgroupRequestCompound {
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    pkiEzsignformfieldgroupID?:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    fkiEzsigndocumentID:number 
    /**
     * 
     * @type {FieldEEzsignformfieldgroupType}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    eEzsignformfieldgroupType:FieldEEzsignformfieldgroupType 
    /**
     * 
     * @type {FieldEEzsignformfieldgroupSignerrequirement}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    eEzsignformfieldgroupSignerrequirement:FieldEEzsignformfieldgroupSignerrequirement 
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    sEzsignformfieldgroupLabel:string 
    /**
     * The step when the Ezsignsigner will be invited to fill the form fields
     * @type {number}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    iEzsignformfieldgroupStep:number 
    /**
     * The default value for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    sEzsignformfieldgroupDefaultvalue:string 
    /**
     * The minimum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    iEzsignformfieldgroupFilledmin:number 
    /**
     * The maximum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    iEzsignformfieldgroupFilledmax:number 
    /**
     * Whether the Ezsignformfieldgroup is read only or not.
     * @type {boolean}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    bEzsignformfieldgroupReadonly:boolean 
    /**
     * The maximum length for the value in the Ezsignformfieldgroup  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {number}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    iEzsignformfieldgroupMaxlength?:number 
    /**
     * Whether the Ezsignformfieldgroup is encrypted in the database or not. Encrypted values are not displayed on the Ezsigndocument. This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {boolean}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    bEzsignformfieldgroupEncrypted?:boolean 
    /**
     * A regular expression to indicate what values are acceptable for the Ezsignformfieldgroup.  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    sEzsignformfieldgroupRegexp?:string 
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    tEzsignformfieldgroupTooltip?:string 
    /**
     * 
     * @type {FieldEEzsignformfieldgroupTooltipposition}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    eEzsignformfieldgroupTooltipposition?:FieldEEzsignformfieldgroupTooltipposition 
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    eEzsignformfieldgroupTextvalidation?:EnumTextvalidation 
    /**
     * 
     * @type {Array<EzsignformfieldgroupsignerRequestCompound>}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    a_objEzsignformfieldgroupsigner:Array<EzsignformfieldgroupsignerRequestCompound> 
    /**
     * 
     * @type {Array<CustomDropdownElementRequestCompound>}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> 
    /**
     * 
     * @type {Array<EzsignformfieldRequestCompound>}
     * @memberof EzsignformfieldgroupRequestCompound
     */
    a_objEzsignformfield:Array<EzsignformfieldRequestCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignformfieldgroupRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldgroupRequestCompound
 */
export class DataObjectEzsignformfieldgroupRequestCompound {
    pkiEzsignformfieldgroupID?:number = undefined
    fkiEzsigndocumentID:number = 0
    eEzsignformfieldgroupType:FieldEEzsignformfieldgroupType = 'Text'
    eEzsignformfieldgroupSignerrequirement:FieldEEzsignformfieldgroupSignerrequirement = 'All'
    sEzsignformfieldgroupLabel:string = ''
    iEzsignformfieldgroupStep:number = 0
    sEzsignformfieldgroupDefaultvalue:string = ''
    iEzsignformfieldgroupFilledmin:number = 0
    iEzsignformfieldgroupFilledmax:number = 0
    bEzsignformfieldgroupReadonly:boolean = false
    iEzsignformfieldgroupMaxlength?:number = undefined
    bEzsignformfieldgroupEncrypted?:boolean = undefined
    sEzsignformfieldgroupRegexp?:string = undefined
    tEzsignformfieldgroupTooltip?:string = undefined
    eEzsignformfieldgroupTooltipposition?:FieldEEzsignformfieldgroupTooltipposition = undefined
    eEzsignformfieldgroupTextvalidation?:EnumTextvalidation = undefined
    a_objEzsignformfieldgroupsigner:Array<EzsignformfieldgroupsignerRequestCompound> = []
    a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> = undefined
    a_objEzsignformfield:Array<EzsignformfieldRequestCompound> = []
}

/**
 * @export 
 * A EzsignformfieldgroupRequestCompound Validation Object
 * @class ValidationObjectEzsignformfieldgroupRequestCompound
 */
export class ValidationObjectEzsignformfieldgroupRequestCompound {
   pkiEzsignformfieldgroupID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eEzsignformfieldgroupType = {
      type: 'enum',
      allowableValues: ['Text','Textarea','Dropdown','Radio','Checkbox'],
      required: true
   }
   eEzsignformfieldgroupSignerrequirement = {
      type: 'enum',
      allowableValues: ['All','One'],
      required: true
   }
   sEzsignformfieldgroupLabel = {
      type: 'string',
      required: true
   }
   iEzsignformfieldgroupStep = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzsignformfieldgroupDefaultvalue = {
      type: 'string',
      required: true
   }
   iEzsignformfieldgroupFilledmin = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignformfieldgroupFilledmax = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsignformfieldgroupReadonly = {
      type: 'boolean',
      required: true
   }
   iEzsignformfieldgroupMaxlength = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   bEzsignformfieldgroupEncrypted = {
      type: 'boolean',
      required: false
   }
   sEzsignformfieldgroupRegexp = {
      type: 'string',
      pattern: '/^\^.*\$$|^$/',
      required: false
   }
   tEzsignformfieldgroupTooltip = {
      type: 'string',
      required: false
   }
   eEzsignformfieldgroupTooltipposition = {
      type: 'enum',
      allowableValues: ['TopLeft','TopCenter','TopRight','MiddleLeft','MiddleRight','BottomLeft','BottomCenter','BottomRight'],
      required: false
   }
   eEzsignformfieldgroupTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
      required: false
   }
   a_objEzsignformfieldgroupsigner = {
      type: 'array',
      required: true
   }
   a_objDropdownElement = {
      type: 'array',
      required: false
   }
   a_objEzsignformfield = {
      type: 'array',
      required: true
   }
} 


