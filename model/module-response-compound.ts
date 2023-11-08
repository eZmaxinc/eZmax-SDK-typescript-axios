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
import { ModuleResponse } from './module-response';
// May contain unused imports in some cases
// @ts-ignore
import { ModulesectionResponseCompound } from './modulesection-response-compound';

/**
 * @type ModuleResponseCompound
 * A Module Object
 * @export
 */
/** export type ModuleResponseCompound = ModuleResponse; */
export interface ModuleResponseCompound {
    /**
     * The unique ID of the Module
     * @type {number}
     * @memberof ModuleResponseCompound
     */
    pkiModuleID:number 
    /**
     * The unique ID of the Modulegroup
     * @type {number}
     * @memberof ModuleResponseCompound
     */
    fkiModulegroupID:number 
    /**
     * The Internal name of the Module.  This is theoretically an enum field but there are so many possibles values we decided not to list them all.
     * @type {string}
     * @memberof ModuleResponseCompound
     */
    eModuleInternalname:string 
    /**
     * The Name of the Module in the language of the requester
     * @type {string}
     * @memberof ModuleResponseCompound
     */
    sModuleNameX:string 
    /**
     * Whether the Module is registered or not
     * @type {boolean}
     * @memberof ModuleResponseCompound
     */
    bModuleRegistered:boolean 
    /**
     * Whether the Module is registered or not for api use
     * @type {boolean}
     * @memberof ModuleResponseCompound
     */
    bModuleRegisteredapi:boolean 
    /**
     * 
     * @type {Array<ModulesectionResponseCompound>}
     * @memberof ModuleResponseCompound
     */
    a_objModulesection?:Array<ModulesectionResponseCompound> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ModuleResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectModuleResponseCompound
 */
export class DataObjectModuleResponseCompound {
    pkiModuleID:number = 0
    fkiModulegroupID:number = 0
    eModuleInternalname:string = ''
    sModuleNameX:string = ''
    bModuleRegistered:boolean = false
    bModuleRegisteredapi:boolean = false
    a_objModulesection?:Array<ModulesectionResponseCompound> = undefined
}

/**
 * @export 
 * A ModuleResponseCompound Validation Object
 * @class ValidationObjectModuleResponseCompound
 */
export class ValidationObjectModuleResponseCompound {
   pkiModuleID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiModulegroupID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   eModuleInternalname = {
      type: 'string',
      required: true
   }
   sModuleNameX = {
      type: 'string',
      required: true
   }
   bModuleRegistered = {
      type: 'boolean',
      required: true
   }
   bModuleRegisteredapi = {
      type: 'boolean',
      required: true
   }
   a_objModulesection = {
      type: 'array',
      required: false
   }
} 

