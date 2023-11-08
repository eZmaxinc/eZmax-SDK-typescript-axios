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
import { FieldESystemconfigurationEzsign } from './field-esystemconfiguration-ezsign';
// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationLanguage1 } from './field-esystemconfiguration-language1';
// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationLanguage2 } from './field-esystemconfiguration-language2';
// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationNewexternaluseraction } from './field-esystemconfiguration-newexternaluseraction';
// May contain unused imports in some cases
// @ts-ignore
import { SystemconfigurationResponse } from './systemconfiguration-response';

/**
 * @type SystemconfigurationResponseCompound
 * A Systemconfiguration Object
 * @export
 */
/** export type SystemconfigurationResponseCompound = SystemconfigurationResponse; */
export interface SystemconfigurationResponseCompound {
    /**
     * The unique ID of the Systemconfiguration
     * @type {number}
     * @memberof SystemconfigurationResponseCompound
     */
    pkiSystemconfigurationID:number 
    /**
     * The unique ID of the Systemconfigurationtype
     * @type {number}
     * @memberof SystemconfigurationResponseCompound
     */
    fkiSystemconfigurationtypeID:number 
    /**
     * The description of the Systemconfigurationtype in the language of the requester
     * @type {string}
     * @memberof SystemconfigurationResponseCompound
     */
    sSystemconfigurationtypeDescriptionX:string 
    /**
     * 
     * @type {FieldESystemconfigurationNewexternaluseraction}
     * @memberof SystemconfigurationResponseCompound
     */
    eSystemconfigurationNewexternaluseraction:FieldESystemconfigurationNewexternaluseraction 
    /**
     * 
     * @type {FieldESystemconfigurationLanguage1}
     * @memberof SystemconfigurationResponseCompound
     */
    eSystemconfigurationLanguage1:FieldESystemconfigurationLanguage1 
    /**
     * 
     * @type {FieldESystemconfigurationLanguage2}
     * @memberof SystemconfigurationResponseCompound
     */
    eSystemconfigurationLanguage2:FieldESystemconfigurationLanguage2 
    /**
     * 
     * @type {FieldESystemconfigurationEzsign}
     * @memberof SystemconfigurationResponseCompound
     */
    eSystemconfigurationEzsign:FieldESystemconfigurationEzsign 
    /**
     * Whether if we allow the creation of personal files in eZsign
     * @type {boolean}
     * @memberof SystemconfigurationResponseCompound
     */
    bSystemconfigurationEzsignpersonnal:boolean 
    /**
     * Whether if we allow SSPR
     * @type {boolean}
     * @memberof SystemconfigurationResponseCompound
     */
    bSystemconfigurationSspr:boolean 
    /**
     * The start date where the system will be in read only
     * @type {string}
     * @memberof SystemconfigurationResponseCompound
     */
    dtSystemconfigurationReadonlyexpirationstart?:string 
    /**
     * The end date where the system will be in read only
     * @type {string}
     * @memberof SystemconfigurationResponseCompound
     */
    dtSystemconfigurationReadonlyexpirationend?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SystemconfigurationResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSystemconfigurationResponseCompound
 */
export class DataObjectSystemconfigurationResponseCompound {
    pkiSystemconfigurationID:number = 0
    fkiSystemconfigurationtypeID:number = 0
    sSystemconfigurationtypeDescriptionX:string = ''
    eSystemconfigurationNewexternaluseraction:FieldESystemconfigurationNewexternaluseraction = 'Stage'
    eSystemconfigurationLanguage1:FieldESystemconfigurationLanguage1 = 'fr_QC'
    eSystemconfigurationLanguage2:FieldESystemconfigurationLanguage2 = 'en_CA'
    eSystemconfigurationEzsign:FieldESystemconfigurationEzsign = 'No'
    bSystemconfigurationEzsignpersonnal:boolean = false
    bSystemconfigurationSspr:boolean = false
    dtSystemconfigurationReadonlyexpirationstart?:string = undefined
    dtSystemconfigurationReadonlyexpirationend?:string = undefined
}

/**
 * @export 
 * A SystemconfigurationResponseCompound Validation Object
 * @class ValidationObjectSystemconfigurationResponseCompound
 */
export class ValidationObjectSystemconfigurationResponseCompound {
   pkiSystemconfigurationID = {
      type: 'integer',
      minimum: 1,
      maximum: 1,
      required: true
   }
   fkiSystemconfigurationtypeID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sSystemconfigurationtypeDescriptionX = {
      type: 'string',
      required: true
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
      required: true
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
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/',
      required: false
   }
   dtSystemconfigurationReadonlyexpirationend = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/',
      required: false
   }
} 

