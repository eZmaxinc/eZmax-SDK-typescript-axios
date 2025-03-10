/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { FieldESystemconfigurationEzsign } from './field-esystemconfiguration-ezsign';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldESystemconfigurationEzsignofficeplan } from './field-esystemconfiguration-ezsignofficeplan';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldESystemconfigurationLanguage1 } from './field-esystemconfiguration-language1';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldESystemconfigurationLanguage2 } from './field-esystemconfiguration-language2';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldESystemconfigurationNewexternaluseraction } from './field-esystemconfiguration-newexternaluseraction';
// May contain unused imports in some cases
// @ts-ignore
import type { SystemconfigurationRequest } from './systemconfiguration-request';

/**
 * @type SystemconfigurationRequestCompound
 * A Systemconfiguration Object and children
 * @export
 */
/*export type SystemconfigurationRequestCompound = SystemconfigurationRequest;*/
export interface SystemconfigurationRequestCompound {
    /**
     * The unique ID of the Systemconfiguration
     * @type {number}
     * @memberof SystemconfigurationRequestCompound
     */
    pkiSystemconfigurationID?:number 
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof SystemconfigurationRequestCompound
     */
    fkiBrandingID?:number 
    /**
     * 
     * @type {FieldESystemconfigurationNewexternaluseraction}
     * @memberof SystemconfigurationRequestCompound
     */
    eSystemconfigurationNewexternaluseraction:FieldESystemconfigurationNewexternaluseraction 
    /**
     * 
     * @type {FieldESystemconfigurationLanguage1}
     * @memberof SystemconfigurationRequestCompound
     */
    eSystemconfigurationLanguage1:FieldESystemconfigurationLanguage1 
    /**
     * 
     * @type {FieldESystemconfigurationLanguage2}
     * @memberof SystemconfigurationRequestCompound
     */
    eSystemconfigurationLanguage2:FieldESystemconfigurationLanguage2 
    /**
     * 
     * @type {FieldESystemconfigurationEzsign}
     * @memberof SystemconfigurationRequestCompound
     * @deprecated
     */
    eSystemconfigurationEzsign?:FieldESystemconfigurationEzsign 
    /**
     * 
     * @type {FieldESystemconfigurationEzsignofficeplan}
     * @memberof SystemconfigurationRequestCompound
     */
    eSystemconfigurationEzsignofficeplan?:FieldESystemconfigurationEzsignofficeplan 
    /**
     * Whether if Ezsign is paid by the company or not
     * @type {boolean}
     * @memberof SystemconfigurationRequestCompound
     */
    bSystemconfigurationEzsignpaidbyoffice?:boolean 
    /**
     * Whether if we allow the creation of personal files in eZsign
     * @type {boolean}
     * @memberof SystemconfigurationRequestCompound
     */
    bSystemconfigurationEzsignpersonnal:boolean 
    /**
     * Whether if we allow SSPR
     * @type {boolean}
     * @memberof SystemconfigurationRequestCompound
     */
    bSystemconfigurationSspr:boolean 
    /**
     * The start date where the system will be in read only
     * @type {string}
     * @memberof SystemconfigurationRequestCompound
     */
    dtSystemconfigurationReadonlyexpirationstart?:string 
    /**
     * The end date where the system will be in read only
     * @type {string}
     * @memberof SystemconfigurationRequestCompound
     */
    dtSystemconfigurationReadonlyexpirationend?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SystemconfigurationRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSystemconfigurationRequestCompound
 */
export class DataObjectSystemconfigurationRequestCompound {
    pkiSystemconfigurationID?:number = undefined
    fkiBrandingID?:number = undefined
    eSystemconfigurationNewexternaluseraction:FieldESystemconfigurationNewexternaluseraction = 'Stage'
    eSystemconfigurationLanguage1:FieldESystemconfigurationLanguage1 = 'fr_QC'
    eSystemconfigurationLanguage2:FieldESystemconfigurationLanguage2 = 'en_CA'
    eSystemconfigurationEzsign?:FieldESystemconfigurationEzsign = undefined
    eSystemconfigurationEzsignofficeplan?:FieldESystemconfigurationEzsignofficeplan = undefined
    bSystemconfigurationEzsignpaidbyoffice?:boolean = undefined
    bSystemconfigurationEzsignpersonnal:boolean = false
    bSystemconfigurationSspr:boolean = false
    dtSystemconfigurationReadonlyexpirationstart?:string = undefined
    dtSystemconfigurationReadonlyexpirationend?:string = undefined
}

/**
 * @export 
 * A SystemconfigurationRequestCompound Validation Object
 * @class ValidationObjectSystemconfigurationRequestCompound
 */
export class ValidationObjectSystemconfigurationRequestCompound {
   pkiSystemconfigurationID = {
      type: 'integer',
      minimum: 1,
      maximum: 1,
      required: false
   }
   fkiBrandingID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eSystemconfigurationNewexternaluseraction = {
      type: 'enum',
      allowableValues: ['Stage','AutoCreate'],
      required: true
   }
   eSystemconfigurationLanguage1 = {
      type: 'enum',
      allowableValues: ['fr_QC'],
      required: true
   }
   eSystemconfigurationLanguage2 = {
      type: 'enum',
      allowableValues: ['en_CA','en_QC','en_US'],
      required: true
   }
   eSystemconfigurationEzsign = {
      type: 'enum',
      allowableValues: ['No','Yes'],
      required: false
   }
   eSystemconfigurationEzsignofficeplan = {
      type: 'enum',
      allowableValues: ['Standard','Pro'],
      required: false
   }
   bSystemconfigurationEzsignpaidbyoffice = {
      type: 'boolean',
      required: false
   }
   bSystemconfigurationEzsignpersonnal = {
      type: 'boolean',
      required: true
   }
   bSystemconfigurationSspr = {
      type: 'boolean',
      required: true
   }
   dtSystemconfigurationReadonlyexpirationstart = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: false
   }
   dtSystemconfigurationReadonlyexpirationend = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: false
   }
} 


