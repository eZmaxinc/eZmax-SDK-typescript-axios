/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipRequest } from './ezsigntemplatepackagesignermembership-request';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagesignermembershipRequestCompound
 * A Ezsigntemplatepackagesignermembership Object and children
 * @export
 */
export type EzsigntemplatepackagesignermembershipRequestCompound = EzsigntemplatepackagesignermembershipRequest;


/**
 * @export 
 * A EzsigntemplatepackagesignermembershipRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagesignermembershipRequestCompound
 */
export class DefaultObjectEzsigntemplatepackagesignermembershipRequestCompound extends DefaultObject {
   pkiEzsigntemplatepackagesignermembershipID?:number = undefined
   fkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatesignerID:number = 0
   iEzsigntemplatepackagesignermembershipCopy?:number = undefined
}


