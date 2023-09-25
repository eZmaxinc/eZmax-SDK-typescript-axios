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
import { CustomDropdownElementResponseCompound } from './custom-dropdown-element-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldResponseCompound } from './ezsignformfield-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupResponse } from './ezsignformfieldgroup-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupsignerResponseCompound } from './ezsignformfieldgroupsigner-response-compound';
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
 * @type EzsignformfieldgroupResponseCompound
 * An Ezsignformfieldgroup Object and children to create a complete structure
 * @export
 */
/** export type EzsignformfieldgroupResponseCompound = EzsignformfieldgroupResponse; */
export interface EzsignformfieldgroupResponseCompound {
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    pkiEzsignformfieldgroupID:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    fkiEzsigndocumentID:number 
    /**
     * 
     * @type {FieldEEzsignformfieldgroupType}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    eEzsignformfieldgroupType:FieldEEzsignformfieldgroupType 
    /**
     * 
     * @type {FieldEEzsignformfieldgroupSignerrequirement}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    eEzsignformfieldgroupSignerrequirement:FieldEEzsignformfieldgroupSignerrequirement 
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    sEzsignformfieldgroupLabel:string 
    /**
     * The step when the Ezsignsigner will be invited to fill the form fields
     * @type {number}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    iEzsignformfieldgroupStep:number 
    /**
     * The default value for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    sEzsignformfieldgroupDefaultvalue?:string 
    /**
     * The minimum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    iEzsignformfieldgroupFilledmin:number 
    /**
     * The maximum number of Ezsignformfield that must be filled in the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    iEzsignformfieldgroupFilledmax:number 
    /**
     * Whether the Ezsignformfieldgroup is read only or not.
     * @type {boolean}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    bEzsignformfieldgroupReadonly:boolean 
    /**
     * The maximum length for the value in the Ezsignformfieldgroup  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {number}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    iEzsignformfieldgroupMaxlength?:number 
    /**
     * Whether the Ezsignformfieldgroup is encrypted in the database or not. Encrypted values are not displayed on the Ezsigndocument. This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {boolean}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    bEzsignformfieldgroupEncrypted?:boolean 
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    eEzsignformfieldgroupTextvalidation?:EnumTextvalidation 
    /**
     * A regular expression to indicate what values are acceptable for the Ezsignformfieldgroup.  This can only be set if eEzsignformfieldgroupType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    sEzsignformfieldgroupRegexp?:string 
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    tEzsignformfieldgroupTooltip?:string 
    /**
     * 
     * @type {FieldEEzsignformfieldgroupTooltipposition}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    eEzsignformfieldgroupTooltipposition?:FieldEEzsignformfieldgroupTooltipposition 
    /**
     * 
     * @type {Array<EzsignformfieldResponseCompound>}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    a_objEzsignformfield:Array<EzsignformfieldResponseCompound> 
    /**
     * 
     * @type {Array<CustomDropdownElementResponseCompound>}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    a_objDropdownElement?:Array<CustomDropdownElementResponseCompound> 
    /**
     * 
     * @type {Array<EzsignformfieldgroupsignerResponseCompound>}
     * @memberof EzsignformfieldgroupResponseCompound
     */
    a_objEzsignformfieldgroupsigner:Array<EzsignformfieldgroupsignerResponseCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignformfieldgroupResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldgroupResponseCompound
 */
export class DataObjectEzsignformfieldgroupResponseCompound {
    pkiEzsignformfieldgroupID:number = 0
    fkiEzsigndocumentID:number = 0
    eEzsignformfieldgroupType:FieldEEzsignformfieldgroupType = 'Text'
    eEzsignformfieldgroupSignerrequirement:FieldEEzsignformfieldgroupSignerrequirement = 'All'
    sEzsignformfieldgroupLabel:string = ''
    iEzsignformfieldgroupStep:number = 0
    sEzsignformfieldgroupDefaultvalue?:string = undefined
    iEzsignformfieldgroupFilledmin:number = 0
    iEzsignformfieldgroupFilledmax:number = 0
    bEzsignformfieldgroupReadonly:boolean = false
    iEzsignformfieldgroupMaxlength?:number = undefined
    bEzsignformfieldgroupEncrypted?:boolean = undefined
    eEzsignformfieldgroupTextvalidation?:EnumTextvalidation = undefined
    sEzsignformfieldgroupRegexp?:string = undefined
    tEzsignformfieldgroupTooltip?:string = undefined
    eEzsignformfieldgroupTooltipposition?:FieldEEzsignformfieldgroupTooltipposition = undefined
    a_objEzsignformfield:Array<EzsignformfieldResponseCompound> = []
    a_objDropdownElement?:Array<CustomDropdownElementResponseCompound> = undefined
    a_objEzsignformfieldgroupsigner:Array<EzsignformfieldgroupsignerResponseCompound> = []
}

/**
 * @export 
 * A EzsignformfieldgroupResponseCompound Validation Object
 * @class ValidationObjectEzsignformfieldgroupResponseCompound
 */
export class ValidationObjectEzsignformfieldgroupResponseCompound {
   pkiEzsignformfieldgroupID = {
      type: 'integer',
      minimum: 0,
      required: true
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
      required: false
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
   eEzsignformfieldgroupTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
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
   a_objEzsignformfield = {
      type: 'array',
      required: true
   }
   a_objDropdownElement = {
      type: 'array',
      required: false
   }
   a_objEzsignformfieldgroupsigner = {
      type: 'array',
      required: true
   }
} 


