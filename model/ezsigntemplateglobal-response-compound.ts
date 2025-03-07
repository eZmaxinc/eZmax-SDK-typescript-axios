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
import type { EzsigntemplateglobalResponse } from './ezsigntemplateglobal-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateglobaldocumentResponse } from './ezsigntemplateglobaldocument-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateglobalsignerResponseCompound } from './ezsigntemplateglobalsigner-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateglobalModule } from './field-eezsigntemplateglobal-module';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateglobalSupplier } from './field-eezsigntemplateglobal-supplier';

/**
 * @type EzsigntemplateglobalResponseCompound
 * A Ezsigntemplateglobal Object
 * @export
 */
/*export type EzsigntemplateglobalResponseCompound = EzsigntemplateglobalResponse;*/
export interface EzsigntemplateglobalResponseCompound {
    /**
     * The unique ID of the Ezsigntemplateglobal
     * @type {number}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    pkiEzsigntemplateglobalID:number 
    /**
     * The unique ID of the Ezsigntemplateglobaldocument
     * @type {number}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    fkiEzsigntemplateglobaldocumentID:number 
    /**
     * The unique ID of the Module
     * @type {number}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    fkiModuleID:number 
    /**
     * The Name of the Module in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    sModuleNameX?:string 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    fkiLanguageID:number 
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    sLanguageNameX:string 
    /**
     * 
     * @type {FieldEEzsigntemplateglobalModule}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    eEzsigntemplateglobalModule:FieldEEzsigntemplateglobalModule 
    /**
     * 
     * @type {FieldEEzsigntemplateglobalSupplier}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    eEzsigntemplateglobalSupplier:FieldEEzsigntemplateglobalSupplier 
    /**
     * The Code of the Ezsigntemplateglobal
     * @type {string}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    sEzsigntemplateglobalCode:string 
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    sEzsigntemplateglobalDescription:string 
    /**
     * 
     * @type {EzsigntemplateglobaldocumentResponse}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    objEzsigntemplateglobaldocument?:EzsigntemplateglobaldocumentResponse 
    /**
     * 
     * @type {Array<EzsigntemplateglobalsignerResponseCompound>}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    a_objEzsigntemplateglobalsigner:Array<EzsigntemplateglobalsignerResponseCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateglobaldocumentResponse } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateglobaldocumentResponse } from './'

/**
 * @export 
 * A EzsigntemplateglobalResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateglobalResponseCompound
 */
export class DataObjectEzsigntemplateglobalResponseCompound {
    pkiEzsigntemplateglobalID:number = 0
    fkiEzsigntemplateglobaldocumentID:number = 0
    fkiModuleID:number = 0
    sModuleNameX?:string = undefined
    fkiLanguageID:number = 0
    sLanguageNameX:string = ''
    eEzsigntemplateglobalModule:FieldEEzsigntemplateglobalModule = 'All'
    eEzsigntemplateglobalSupplier:FieldEEzsigntemplateglobalSupplier = 'Centris'
    sEzsigntemplateglobalCode:string = ''
    sEzsigntemplateglobalDescription:string = ''
    objEzsigntemplateglobaldocument?:EzsigntemplateglobaldocumentResponse = undefined
    a_objEzsigntemplateglobalsigner:Array<EzsigntemplateglobalsignerResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplateglobalResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplateglobalResponseCompound
 */
export class ValidationObjectEzsigntemplateglobalResponseCompound {
   pkiEzsigntemplateglobalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplateglobaldocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiModuleID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sModuleNameX = {
      type: 'string',
      required: false
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sLanguageNameX = {
      type: 'string',
      required: true
   }
   eEzsigntemplateglobalModule = {
      type: 'enum',
      allowableValues: ['All','Inscription'],
      required: true
   }
   eEzsigntemplateglobalSupplier = {
      type: 'enum',
      allowableValues: ['Centris','Webforms','GHACQ'],
      required: true
   }
   sEzsigntemplateglobalCode = {
      type: 'string',
      pattern: /^.{0,10}$/,
      required: true
   }
   sEzsigntemplateglobalDescription = {
      type: 'string',
      required: true
   }
   objEzsigntemplateglobaldocument = new ValidationObjectEzsigntemplateglobaldocumentResponse()
   a_objEzsigntemplateglobalsigner = {
      type: 'array',
      required: true
   }
} 


